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
SOURCE = 'https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/vless.txt'
LIMIT = 24


def parse_link(line):
    """Only literal public IP + UUID + TCP/TLS or TCP/REALITY, fail closed."""
    url = urllib.parse.urlsplit(line.strip())
    if url.scheme != 'vless' or url.password:
        raise ValueError('not_vless')
    ip = ipaddress.ip_address(url.hostname)
    if not ip.is_global:
        raise ValueError('non_public_ip')
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
    if (q.get('type', 'tcp') != 'tcp' or q.get('headerType', 'none') != 'none'
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
            'settings': {'vnext': [{'address': str(ip), 'port': port, 'users': [user]}]},
            'streamSettings': {'network': 'tcp', 'security': q['security'],
                               ('realitySettings' if q['security'] == 'reality' else 'tlsSettings'): tls}}


def registration(ip):
    try:
        with urllib.request.urlopen('https://rdap.db.ripe.net/ip/' + ip, timeout=10) as response:
            country = json.load(response).get('country', '')
        return ip, country if re.fullmatch('[A-Z]{2}', country or '') else None
    except Exception:
        return ip, None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--xray', required=True)
    parser.add_argument('--assets', required=True)
    args = parser.parse_args()
    rejected = Counter()
    with urllib.request.urlopen(SOURCE, timeout=30) as response:
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise SystemExit('Source exceeds size limit')
    working = clients.read_json(ROOT / 'whitelist_configs_combined.json')
    existing_hosts = {clients.server_host(o) for _, o in clients.nodes(working)}
    nets = [ipaddress.ip_network(n) for rule in clients.read_json(ROOT / 'rules/geoip-ru.json')['rules']
            for n in rule['ip_cidr']]
    candidates, seen = [], set()
    for line in raw.decode('utf-8-sig').splitlines()[:2000]:
        try:
            outbound = parse_link(line)
            host = clients.server_host(outbound)
            ip = ipaddress.ip_address(host)
            if host in existing_hosts or host in seen:
                rejected['duplicate_or_existing_host'] += 1
                continue
            if any(ip.version == n.version and ip in n for n in nets):
                rejected['russian_geoip'] += 1
                continue
            seen.add(host)
            candidates.append(outbound)
        except (ValueError, TypeError, AttributeError):
            rejected['unsupported_or_unsafe_link'] += 1
        if len(candidates) >= 60:
            break
    with ThreadPoolExecutor(max_workers=4) as pool:
        countries = dict(pool.map(registration, [clients.server_host(o) for o in candidates]))
    safe = [o for o in candidates if countries[clients.server_host(o)] not in (None, 'RU')]
    rejected['russian_or_unknown_registration'] = len(candidates) - len(safe)
    policy = clients.routing_policy(working)
    template = clients.read_json(ROOT / 'subscription.txt')[1]
    good, results = [], []
    with tempfile.TemporaryDirectory(prefix='vpn-test-trial-') as directory:
        for index, outbound in enumerate(safe[:LIMIT], 1):
            host = clients.server_host(outbound)
            name = f"🧪 {countries[host]} · {clients.node_key(outbound)[:6]}"
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
            print(f'{index}/{min(len(safe), LIMIT)} {name}: {metric["status"]}', flush=True)
            if metric['status'] == 'ok':
                config['remarks'] += f" | тест: ≈{metric['speed_mbps']:.2f} Мбит/с · {metric['latency_ms']} мс"
                good.append((metric['speed_mbps'], config))
    report = {'source': SOURCE, 'source_sha256': hashlib.sha256(raw).hexdigest(),
              'measured_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'vantage': 'GitHub Actions' if os.environ.get('GITHUB_ACTIONS') else 'local machine',
              'rejected': dict(rejected), 'measurements': results, 'published_nodes': min(len(good), 10),
              'note': 'Only public-IP TCP VLESS TLS/REALITY subset. Not proof of Telegram access or operator trust.'}
    if not good:
        raise SystemExit('No successful trial nodes; previous experimental subscription untouched')
    payload = [config for _, config in sorted(good, key=lambda item: item[0], reverse=True)[:10]]
    (ROOT / 'subscription_experimental.txt').write_text(clients.json_text(payload), encoding='utf-8')
    (ROOT / 'experimental_report.json').write_text(clients.json_text(report), encoding='utf-8')
    print(f'Published {len(payload)} experimental profiles; working feeds untouched')


if __name__ == '__main__':
    main()
