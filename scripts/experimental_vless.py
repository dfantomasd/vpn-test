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
    ('internet-tenshi-whitelist', 'https://internet-tenshi.kangel.tech/whitelist'),
    ('zieng2-whitelist', 'https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt'),
    ('AirLink-whitelist', 'https://raw.githubusercontent.com/AirLinkVPN1/AirLinkVPN/main/rkn_white_list'),
    ('HardVPN-whitelist', 'https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/main/vpn-lte/WHITELIST-ALL.txt'),
    ('Generation-Liberty', 'https://raw.githubusercontent.com/gergew452/Generation-Liberty/main/githubmirror/best.txt'),
    ('igareck-white-sni', 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt'),
    ('AvenCores-whitelist-pool', 'https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/26.txt'),
    ('vpn-config-rkn-checked', 'https://raw.githubusercontent.com/vsvavan2/vpn-config-rkn/main/output/all_working_keys.txt'),
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
MAX_PUBLISHED = 5
CURATED_MOBILE_SOURCES = {
    'internet-tenshi-whitelist', 'zieng2-whitelist', 'AirLink-whitelist',
    'HardVPN-whitelist', 'Generation-Liberty', 'igareck-white-sni',
    'AvenCores-whitelist-pool', 'vpn-config-rkn-checked',
}

# Public services commonly reachable when Russian mobile operators switch to an
# allow-list. This is only a candidate fingerprint, not proof of reachability.
WHITELIST_SNI_SUFFIXES = (
    '.ru', '.yandex.net', '.yandex.com', '.vk.com', '.vk-portal.net',
    '.ok.ru', '.mail.ru', '.ozone.ru', '.sirius.online', '.gosuslugi.ru',
    '.tbank.ru', '.sberbank.ru', '.wb.ru', '.rutube.ru', '.2gis.com',
    '.lmru.tech',
)


def is_whitelist_profile(outbound):
    """Select the Reality/TCP-or-XHTTP shape seen in working mobile profiles."""
    stream = outbound['streamSettings']
    tls = stream.get('realitySettings', {})
    sni = tls.get('serverName', '').lower().rstrip('.')
    return (stream.get('security') == 'reality'
            and stream.get('network') in ('tcp', 'xhttp')
            and any(sni == suffix[1:] or sni.endswith(suffix)
                    for suffix in WHITELIST_SNI_SUFFIXES))


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
               'pbk', 'sid', 'spx', 'alpn', 'allowInsecure', 'insecure',
               'path', 'host', 'mode', 'extra'}
    if set(pairs) - allowed or any(len(v) != 1 for v in pairs.values()):
        raise ValueError('unsupported_parameters')
    q = {k: v[0] for k, v in pairs.items()}
    transport = q.get('type', 'tcp')
    if (transport not in ('tcp', 'raw', 'xhttp') or q.get('headerType', 'none') != 'none'
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
    network = 'tcp' if transport == 'raw' else transport
    stream = {'network': network, 'security': q['security'],
              ('realitySettings' if q['security'] == 'reality' else 'tlsSettings'): tls}
    if network == 'xhttp':
        mode = q.get('mode', 'auto')
        if mode not in ('auto', 'packet-up', 'stream-up', 'stream-one'):
            raise ValueError('invalid_xhttp_mode')
        xhttp = {'path': q.get('path', '/'), 'host': q.get('host', ''), 'mode': mode}
        if q.get('extra'):
            try:
                extra = json.loads(q['extra'])
            except json.JSONDecodeError as exc:
                raise ValueError('invalid_xhttp_extra') from exc
            if not isinstance(extra, dict):
                raise ValueError('invalid_xhttp_extra')
            xhttp['extra'] = extra
        stream['xhttpSettings'] = xhttp
    return {'tag': 'proxy', 'protocol': 'vless',
            'settings': {'vnext': [{'address': host, 'port': port, 'users': [user]}]},
            'streamSettings': stream}


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
    successes_path = ROOT / 'experimental_mobile_successes.json'
    mobile_successes = set(clients.read_json(successes_path).get('node_keys', [])) if successes_path.exists() else set()
    existing_hosts = {clients.server_host(o) for _, o in clients.nodes(working)}
    nets = [ipaddress.ip_network(n) for rule in clients.read_json(ROOT / 'rules/geoip-ru.json')['rules']
            for n in rule['ip_cidr']]
    candidates, seen, seen_candidate_hosts, source_hashes = [], set(), set(), {}
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
                if not is_whitelist_profile(outbound):
                    rejected[source + ':not_mobile_whitelist_profile'] += 1
                    continue
                host = clients.server_host(outbound)
                identity = clients.node_key(outbound)
                if identity in mobile_failures:
                    rejected[source + ':failed_iphone_telegram'] += 1
                    continue
                if host in existing_hosts or host in seen_candidate_hosts or identity in seen:
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
                seen_candidate_hosts.add(host)
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
    good, mobile_trials, results = [], [], []
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
            # A white-list endpoint can deliberately be unreachable from a
            # foreign GitHub runner while remaining reachable on Russian LTE.
            # Keep a bounded, clearly labelled iPhone trial pool after Xray
            # validates the complete configuration.
            trial = copy.deepcopy(config)
            key = clients.node_key(outbound)
            if key in mobile_successes:
                trial['remarks'] = f"✅ iPhone Telegram · с задержкой · {country} · {source} · {key[:6]}"
            else:
                trial['remarks'] = f"📱 ПРОВЕРИТЬ iPhone · {country} · {source} · {key[:6]}"
            mobile_trials.append((source, trial))
            _, metric = probes.measure((name, outbound), args.mihomo)
            results.append({'name': name, **metric})
            print(f'{index}/{len(safe)} {name}: {metric["status"]}', flush=True)
            if (metric['status'] == 'ok' and metric['speed_mbps'] >= MIN_SPEED_MBPS
                    and metric['latency_ms'] <= MAX_LATENCY_MS):
                config['remarks'] += f" | тест: ≈{metric['speed_mbps']:.2f} Мбит/с · {metric['latency_ms']} мс"
                good.append((metric['speed_mbps'], config))
    confirmed = [config for _, config in mobile_trials
                 if clients.node_key(next(o for o in config['outbounds'] if o.get('protocol') == 'vless'))
                 in mobile_successes]
    verified = [config for _, config in sorted(good, key=lambda item: item[0], reverse=True)
                if clients.node_key(next(o for o in config['outbounds'] if o.get('protocol') == 'vless'))
                not in mobile_successes]
    selected_keys = {clients.node_key(next(o for o in c['outbounds'] if o.get('protocol') == 'vless'))
                     for c in confirmed + verified}
    curated = [item for item in mobile_trials if item[0] in CURATED_MOBILE_SOURCES]
    other = [item for item in mobile_trials if item[0] not in CURATED_MOBILE_SOURCES]
    fallback = []
    used_sources = set()
    # Source diversity first, then fill remaining slots in stable source order.
    for source, config in curated + other:
        key = clients.node_key(next(o for o in config['outbounds'] if o.get('protocol') == 'vless'))
        if key in selected_keys or source in used_sources:
            continue
        fallback.append(config)
        selected_keys.add(key)
        used_sources.add(source)
    for source, config in curated + other:
        key = clients.node_key(next(o for o in config['outbounds'] if o.get('protocol') == 'vless'))
        if key not in selected_keys:
            fallback.append(config)
            selected_keys.add(key)
    payload = (confirmed + verified + fallback)[:MAX_PUBLISHED]
    report = {'sources': [{'name': name, 'url': url, 'sha256': source_hashes.get(name)}
                          for name, url in SOURCES],
              'measured_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'vantage': 'GitHub Actions' if os.environ.get('GITHUB_ACTIONS') else 'local machine',
              'quality_thresholds': {'min_speed_mbps': MIN_SPEED_MBPS,
                                     'max_latency_ms': MAX_LATENCY_MS},
              'rejected': dict(rejected), 'measurements': results,
              'published_nodes': len(payload),
              'iphone_confirmed_nodes': min(len(confirmed), MAX_PUBLISHED),
              'externally_verified_nodes': min(len(verified), max(0, MAX_PUBLISHED - len(confirmed))),
              'iphone_trial_nodes': sum(c['remarks'].startswith('📱') for c in payload),
              'note': ('Foreign VLESS Reality white-list candidates. Names beginning with '
                       '"ПРОВЕРИТЬ iPhone" passed structural/Xray validation but are intentionally '
                       'not claimed to work until tested on Russian mobile access.')}
    (ROOT / 'subscription_experimental.txt').write_text(clients.json_text(payload), encoding='utf-8')
    (ROOT / 'experimental_report.json').write_text(clients.json_text(report), encoding='utf-8')
    print(f'Published {len(payload)} qualifying experimental profiles; working feeds untouched')


if __name__ == '__main__':
    main()
