"""Bounded, isolated trial feed. Never writes the working subscriptions."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import copy
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import base64
import socket
import subprocess
import tempfile
import urllib.parse
import urllib.request
import uuid

try:
    from . import build_clients as clients
    from . import measure_nodes as probes
except ImportError:
    import build_clients as clients
    import measure_nodes as probes

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [
    ('igareck', 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt'),
    ('Au1rxx', 'https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt'),
    ('morpheus', 'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/reality.txt'),
    ('Vovaplus', 'https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Secure/vless.txt'),
    ('Radikal', 'https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless.txt'),
    ('aviamasters', 'https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia/main/verified_configs.txt'),
]
PER_SOURCE_LIMIT = 5
MAX_SOURCE_BYTES = 4_000_000
MIN_SPEED_MBPS = 1.5
MAX_LATENCY_MS = 1500


def parse_link(line):
    """Only literal public IP + UUID + TCP/TLS or TCP/REALITY, fail closed."""
    url = urllib.parse.urlsplit(line.strip())
    if url.scheme != 'vless' or url.password:
        raise ValueError('not_vless')
    host = url.hostname or ''
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
            raise ValueError('invalid_hostname')
    else:
        if not ip.is_global:
            raise ValueError('non_public_ip')
        host = str(ip)
    secret = str(uuid.UUID(urllib.parse.unquote(url.username or '')))
    port = url.port
    if not port or not 1 <= port <= 65535:
        raise ValueError('invalid_port')
    pairs = urllib.parse.parse_qs(url.query, keep_blank_values=True)
    allowed = {'security', 'encryption', 'type', 'headerType', 'fp', 'flow', 'sni',
               'pbk', 'sid', 'spx', 'alpn', 'allowInsecure', 'insecure'}
    if set(pairs) - allowed or any(len(v) != 1 for v in pairs.values()):
        raise ValueError('unsupported_parameters')
    q = {k: v[0] for k, v in pairs.items()}
    transport = q.get('type', 'tcp')
    if (transport not in ('tcp', 'raw') or q.get('headerType', 'none') != 'none'
            or q.get('encryption', 'none') != 'none'
            or q.get('security') not in ('tls', 'reality')
            or any(q.get(k, '0').lower() not in ('0', 'false', '') for k in ('insecure', 'allowInsecure'))):
        raise ValueError('unsupported_or_insecure_transport')
    label = urllib.parse.unquote(url.fragment)
    if '🇷🇺' in label or re.search(r'\bRU\b|russia|россия', label, re.I):
        raise ValueError('russian_label')
    if not q.get('sni') or not re.fullmatch(r'[A-Za-z0-9.-]+', q['sni']):
        raise ValueError('missing_or_invalid_sni')
    tls = {'serverName': q['sni'], 'fingerprint': q.get('fp', 'chrome')}
    if q.get('alpn'):
        tls['alpn'] = q['alpn'].split(',')
    if q['security'] == 'reality':
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', q.get('pbk', '')):
            raise ValueError('invalid_reality_key')
        sid = q.get('sid', '')
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', sid):
            raise ValueError('invalid_short_id')
        tls.update(publicKey=q['pbk'], shortId=sid, spiderX=q.get('spx', '/'))
    user = {'id': secret, 'encryption': 'none'}
    if q.get('flow'):
        if q['flow'] != 'xtls-rprx-vision':
            raise ValueError('unsupported_flow')
        user['flow'] = q['flow']
    return {'tag': 'proxy', 'protocol': 'vless',
            'settings': {'vnext': [{'address': host, 'port': port, 'users': [user]}]},
            'streamSettings': {'network': 'tcp', 'security': q['security'],
                               ('realitySettings' if q['security'] == 'reality' else 'tlsSettings'): tls}}


def registration(ip):
    try:
        with urllib.request.urlopen('https://rdap.org/ip/' + ip, timeout=10) as response:
            country = json.load(response).get('country', '')
        return ip, country if re.fullmatch('[A-Z]{2}', country or '') else None
    except Exception:
        return ip, None


def source_lines(raw):
    text = raw.decode('utf-8-sig').strip()
    if not any(line.lstrip().startswith('vless://') for line in text.splitlines()):
        try:
            text = base64.b64decode(''.join(text.split()), validate=True).decode('utf-8-sig')
        except Exception as exc:
            raise ValueError('Source is neither URI list nor strict base64 URI list') from exc
    return text.splitlines()


def endpoint_ips(host):
    try:
        ip = ipaddress.ip_address(host)
        return [str(ip)] if ip.is_global else []
    except ValueError:
        try:
            return sorted({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                           if ipaddress.ip_address(item[4][0]).is_global})
        except socket.gaierror:
            return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--xray', required=True)
    parser.add_argument('--assets', required=True)
    args = parser.parse_args()
    rejected = Counter()
    working = clients.read_json(ROOT / 'whitelist_configs_combined.json')
    failures_path = ROOT / 'experimental_mobile_failures.json'
    mobile_failures = set(clients.read_json(failures_path).get('node_keys', [])) if failures_path.exists() else set()
    existing_hosts = {clients.server_host(o) for _, o in clients.nodes(working)}
    nets = [ipaddress.ip_network(n) for rule in clients.read_json(ROOT / 'rules/geoip-ru.json')['rules']
            for n in rule['ip_cidr']]
    candidates, seen, source_hashes = [], set(), {}
    for source, url in SOURCES:
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            rejected[source + ':source_too_large'] += 1
            continue
        source_hashes[source] = hashlib.sha256(raw).hexdigest()
        accepted = 0
        for line in source_lines(raw)[:20000]:
            try:
                outbound = parse_link(line)
                host = clients.server_host(outbound)
                identity = clients.node_key(outbound)
                if identity in mobile_failures:
                    rejected[source + ':failed_iphone_telegram'] += 1
                    continue
                if host in existing_hosts or identity in seen:
                    rejected[source + ':duplicate_or_existing'] += 1
                    continue
                addresses = endpoint_ips(host)
                if not addresses:
                    raise ValueError('unresolved')
                if any(any(ipaddress.ip_address(ip).version == n.version and ipaddress.ip_address(ip) in n
                           for n in nets) for ip in addresses):
                    rejected[source + ':russian_geoip'] += 1
                    continue
                seen.add(identity)
                candidates.append((source, outbound, addresses))
                accepted += 1
            except (ValueError, TypeError, AttributeError):
                rejected[source + ':unsupported_or_unsafe'] += 1
            if accepted >= PER_SOURCE_LIMIT:
                break
    all_ips = sorted({ip for _, _, addresses in candidates for ip in addresses})
    with ThreadPoolExecutor(max_workers=4) as pool:
        countries = dict(pool.map(registration, all_ips))
    safe = []
    for source, outbound, addresses in candidates:
        values = {countries[ip] for ip in addresses}
        if None in values or 'RU' in values or len(values) != 1:
            rejected[source + ':russian_unknown_or_mixed_registration'] += 1
        else:
            safe.append((source, outbound, values.pop()))
    policy = clients.routing_policy(working)
    template = clients.read_json(ROOT / 'subscription.txt')[1]
    good, results = [], []
    with tempfile.TemporaryDirectory(prefix='vpn-test-trial-') as directory:
        for index, (source, outbound, country) in enumerate(safe, 1):
            host = clients.server_host(outbound)
            name = f"🧪 {source} · {country} · {clients.node_key(outbound)[:6]}"
            config = {'remarks': name, 'inbounds': copy.deepcopy(template['inbounds']),
                      'outbounds': [outbound, {'tag': 'direct', 'protocol': 'freedom',
                                              'settings': {'domainStrategy': 'UseIP'}}],
                      'routing': clients.happ_routing(policy, {'outboundTag': 'proxy'}),
                      'dns': clients.happ_dns(policy)}
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps(config))
            checked = subprocess.run([args.xray, 'run', '-test', '-c', str(path)],
                env=dict(os.environ, XRAY_LOCATION_ASSET=str(Path(args.assets).resolve())),
                capture_output=True, timeout=20)
            if checked.returncode:
                rejected['xray_rejected'] += 1
                continue
            _, metric = probes.measure((name, outbound), args.mihomo)
            results.append({'name': name, **metric})
            print(f'{index}/{len(safe)} {name}: {metric["status"]}', flush=True)
            if (metric['status'] == 'ok' and metric['speed_mbps'] >= MIN_SPEED_MBPS
                    and metric['latency_ms'] <= MAX_LATENCY_MS):
                config['remarks'] += f" | тест: ≈{metric['speed_mbps']:.2f} Мбит/с · {metric['latency_ms']} мс"
                good.append((metric['speed_mbps'], config))
    report = {'sources': [{'name': name, 'url': url, 'sha256': source_hashes.get(name)}
                          for name, url in SOURCES],
              'measured_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'vantage': 'GitHub Actions' if os.environ.get('GITHUB_ACTIONS') else 'local machine',
              'quality_thresholds': {'min_speed_mbps': MIN_SPEED_MBPS,
                                     'max_latency_ms': MAX_LATENCY_MS},
              'rejected': dict(rejected), 'measurements': results, 'published_nodes': min(len(good), 10),
              'note': 'Only resolved TCP VLESS TLS/REALITY subset. Not proof of Telegram access or operator trust.'}
    payload = [config for _, config in sorted(good, key=lambda item: item[0], reverse=True)[:10]]
    (ROOT / 'subscription_experimental.txt').write_text(clients.json_text(payload), encoding='utf-8')
    (ROOT / 'experimental_report.json').write_text(clients.json_text(report), encoding='utf-8')
    print(f'Published {len(payload)} qualifying experimental profiles; working feeds untouched')


if __name__ == '__main__':
    main()
