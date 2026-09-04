import base64
import copy
import ipaddress
import json
import re
import unittest
import urllib.parse
from unittest.mock import patch

from scripts import build_clients as clients


def parse_generated_yaml(text):
    # Generator writes YAML block lists with JSON flow values. Independent
    # format validation is also performed with Ruby Psych / Mihomo locally.
    result = {}
    key = None
    for line in text.splitlines():
        if line.startswith('  - '):
            result[key].append(json.loads(line[4:]))
        else:
            key, value = line.split(':', 1)
            result[key] = json.loads(value) if value.strip() else []
    return result


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outputs = clients.build()
        cls.catalog = clients.read_json(clients.ROOT / 'whitelist_configs_combined.json')
        cls.policy = json.loads(cls.outputs['routing_russia.json'])
        cls.karing = parse_generated_yaml(cls.outputs['subscription_karing.txt'])

    def test_artifacts_current(self):
        for name, expected in self.outputs.items():
            self.assertEqual((clients.ROOT / name).read_text(encoding='utf-8'), expected)

    def test_happ_russia_enabled(self):
        configs = json.loads(self.outputs['subscription.txt'])
        self.assertTrue(configs)
        for config in configs:
            domains = [rule['domain'] for rule in config['routing']['rules']
                       if rule.get('outboundTag') == 'direct' and 'domain' in rule]
            self.assertTrue(domains)
            self.assertIn('geosite:category-ru', domains[0])
            self.assertIn('domain:ru', domains[0])

    def test_happ_credentials_preserved(self):
        exported = json.loads(self.outputs['subscription.txt'])
        expected, _ = clients.happ_json_configs(self.catalog)
        self.assertEqual(exported, expected)

    def test_karing_groups_and_default(self):
        self.assertEqual(self.karing['mode'], 'rule')
        self.assertEqual(self.karing['rules'][-1], 'MATCH,VPN_BEST')
        names = [p['name'] for p in self.karing['proxies']]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(self.karing['proxy-groups'][0]['proxies'][1:]), set(names))
        self.assertEqual(self.karing['proxy-groups'][1]['type'], 'url-test')
        self.assertEqual(set(self.karing['proxy-groups'][1]['proxies']), set(names))
        self.assertNotIn('DIRECT', self.karing['proxy-groups'][0]['proxies'])
        self.assertNotIn('dns', self.karing)  # Karing ignores subscription DNS

    def test_domain_routes(self):
        def karing_route(domain):
            for line in self.karing['rules']:
                parts = line.split(',')
                if parts[0] == 'DOMAIN' and domain == parts[1]:
                    return parts[2]
                if parts[0] == 'DOMAIN-SUFFIX' and (domain == parts[1] or domain.endswith('.' + parts[1])):
                    return parts[2]
            return 'VPN_BEST'
        for domain in ('sberbank.ru', 'online.sberbank.ru', 'tbank.ru', 'vtb.com',
                       'alfabank.ru', 'gosuslugi.ru', 'mos.ru', 'nspk.ru', 'ya.ru',
                       'ozon.ru', 'example.su', 'example.xn--p1ai'):
            with self.subTest(domain=domain):
                self.assertEqual(karing_route(domain), 'DIRECT')
        for domain in ('youtube.com', 'googlevideo.com', 'openai.com', 'github.com',
                       'ipinfo.io', 'ifconfig.me', 'browserleaks.com', 'steampowered.com',
                       'sberbank.ru.attacker.example'):
            with self.subTest(domain=domain):
                self.assertEqual(karing_route(domain), 'VPN_BEST')

    def test_geodata_coverage(self):
        rules = set(self.karing['rules'])
        geo = clients.read_json(clients.ROOT / 'rules/category-ru.json')
        for group in geo['rules']:
            for domain in group.get('domain', []):
                if domain not in clients.REMOVE_DIRECT:
                    self.assertIn('DOMAIN,' + domain + ',DIRECT', rules)
            for suffix in group.get('domain_suffix', []):
                suffix = suffix.lstrip('.')
                if suffix not in clients.REMOVE_DIRECT:
                    self.assertIn('DOMAIN-SUFFIX,' + suffix + ',DIRECT', rules)
        for group in clients.read_json(clients.ROOT / 'rules/geoip-ru.json')['rules']:
            for cidr in group['ip_cidr']:
                kind = 'IP-CIDR6' if ipaddress.ip_network(cidr).version == 6 else 'IP-CIDR'
                self.assertIn(kind + ',' + cidr + ',DIRECT', rules)

    def test_no_legacy_foreign_direct_rules(self):
        for domain in clients.REMOVE_DIRECT:
            self.assertNotIn('domain:' + domain, self.policy['DirectSites'])
        for expression in self.policy['DirectSites']:
            if expression.startswith('regexp:'):
                re.compile(expression[7:])

    def test_chains_fail_closed(self):
        name, outbound = clients.nodes(self.catalog)[0]
        outbound = copy.deepcopy(outbound)
        outbound['proxySettings'] = {'tag': 'another'}
        with self.assertRaises(ValueError):
            clients.connection(name, outbound)

    def test_no_tls_verification_disabled(self):
        for proxy in self.karing['proxies']:
            self.assertFalse(proxy.get('skip-cert-verify', False))
        for line in self.outputs['subscription.txt'].splitlines():
            self.assertNotIn('insecure=1', line)

    def test_no_russian_servers(self):
        selected, excluded = clients.foreign_nodes(self.catalog)
        self.assertTrue(any('Россия' in node['name'] for node in excluded))
        self.assertTrue(any('GeoIP RU' in node['reason'] for node in excluded))
        self.assertTrue(any('RDAP RU' in node['reason'] for node in excluded))
        for name, _ in selected:
            self.assertNotIn('Россия', name)
            self.assertNotIn('🇷🇺', name)
        denied_hosts = {entry['server'] for entry in excluded}
        for proxy in self.karing['proxies']:
            self.assertNotIn(proxy['server'], denied_hosts)
        for line in self.outputs['subscription.txt'].splitlines():
            self.assertNotIn('🇷🇺', line)

    def test_subscriptions_vless_only(self):
        configs = json.loads(self.outputs['subscription.txt'])
        protocols = [outbound['protocol'] for config in configs for outbound in config['outbounds']
                     if outbound['protocol'] not in ('freedom', 'blackhole')]
        self.assertTrue(protocols)
        self.assertEqual(set(protocols), {'vless'})
        self.assertTrue(all(proxy['type'] == 'vless' for proxy in self.karing['proxies']))

    def test_happ_native_auto_profile_preserved_first(self):
        configs = json.loads(self.outputs['subscription.txt'])
        auto = configs[0]
        self.assertEqual(auto['remarks'], '🔄 Авто')
        proxies = [o for o in auto['outbounds'] if o['protocol'] == 'vless']
        self.assertGreaterEqual(len(proxies), 2)
        self.assertEqual(len({o['tag'] for o in proxies}), len(proxies))
        balancer = auto['routing']['balancers'][0]
        self.assertIn(balancer['fallbackTag'], {o['tag'] for o in proxies})
        self.assertTrue(all(o['tag'].startswith('auto-node-') for o in proxies))
        self.assertEqual(auto['burstObservatory']['subjectSelector'], ['auto-node-'])
        safe, _ = clients.foreign_nodes(self.catalog)
        self.assertLessEqual({clients.node_key(o) for o in proxies}, {clients.node_key(o) for _, o in safe})

    def test_happ_excludes_unsafe_profiles_whole(self):
        configs, excluded = clients.happ_json_configs(self.catalog)
        names = {config['remarks'] for config in configs}
        self.assertFalse(any('Россия' in name or '🇷🇺' in name for name in names))
        self.assertTrue(any(item['reason'] == 'Contains non-VLESS outbound' for item in excluded))
        self.assertTrue(any(item['reason'].startswith('Contains Russian') for item in excluded))

    def test_non_vless_filtered_before_conversion(self):
        vless = {'protocol': 'vless', 'tag': 'proxy'}
        catalog = [{'remarks': 'mixed', 'outbounds': [vless, {'protocol': 'hysteria'},
                    {'protocol': 'trojan'}, {'protocol': 'vmess'}, {'protocol': 'shadowsocks'}]}]
        self.assertEqual(clients.nodes(catalog), [('mixed', vless)])

    def test_measurement_expiry(self):
        report = {'measured_at': '2026-09-04T00:00:00+00:00'}
        self.assertTrue(clients.measurements_fresh(report, '2026-09-04T05:59:00+00:00'))
        self.assertFalse(clients.measurements_fresh(report, '2026-09-04T06:01:00+00:00'))
        self.assertFalse(clients.measurements_fresh(report, '2026-09-03T23:59:00+00:00'))
        self.assertFalse(clients.measurements_fresh({}, '2026-09-04T00:00:00+00:00'))

    def test_unknown_registration_is_excluded(self):
        read = clients.read_json
        def without_registration(path):
            return {} if path.name == 'server_registration.json' else read(path)
        with patch.object(clients, 'read_json', side_effect=without_registration):
            with self.assertRaisesRegex(ValueError, 'No non-Russian nodes'):
                clients.foreign_nodes(self.catalog)

    def test_karing_conversion_failure_does_not_block_happ(self):
        original = clients.connection
        calls = []
        def unsupported_first(name, outbound):
            calls.append(name)
            if len(calls) == 1:
                raise ValueError('Unsupported transport: ws')
            return original(name, outbound)
        with patch.object(clients, 'connection', side_effect=unsupported_first):
            outputs = clients.build()
        self.assertEqual(outputs['subscription.txt'], self.outputs['subscription.txt'])
        report = json.loads(outputs['build_report.json'])
        self.assertEqual(len(report['karing_conversion_excluded']), 1)
        self.assertGreater(report['karing_nodes'], 0)

    def test_stale_intermediate_build_keeps_winner_state(self):
        reference = clients.read_json(clients.ROOT / 'measurements.json')['measured_at']
        stale_time = (clients.datetime.datetime.fromisoformat(reference) +
                      clients.datetime.timedelta(hours=7)).isoformat()
        stale = clients.build(stale_time)
        self.assertEqual(stale['subscription.txt'], self.outputs['subscription.txt'])
        self.assertNotIn('Мбит/с', stale['subscription_karing.txt'])

    def test_happ_telegram_priority_and_russia_routes(self):
        for config in json.loads(self.outputs['subscription.txt']):
            rules = config['routing']['rules']
            self.assertIn('geosite:telegram', rules[0]['domain'])
            self.assertIn('geoip:telegram', rules[1]['ip'])
            self.assertNotEqual(rules[0].get('outboundTag'), 'direct')
            self.assertIn('domain:ru', rules[2]['domain'])
            self.assertIn('geoip:ru', rules[3]['ip'])
            self.assertEqual(rules[2]['outboundTag'], 'direct')
            self.assertEqual(rules[3]['outboundTag'], 'direct')
            self.assertNotEqual(rules[-1].get('outboundTag'), 'direct')
            self.assertNotIn('domain:ifconfig.me', rules[2]['domain'])
            self.assertFalse(any(r.get('outboundTag') == 'block' for r in rules))

    def test_no_fake_auto_when_only_one_safe_server(self):
        manual = json.loads(self.outputs['subscription.txt'])[1]
        with self.assertRaisesRegex(ValueError, 'At least two'):
            clients.happ_json_configs([manual])

    def test_happ_manual_connection_preserved(self):
        for config in json.loads(self.outputs['subscription.txt'])[1:]:
            source = next(c for c in self.catalog if c['remarks'] == config['remarks'])
            self.assertEqual(config['outbounds'], source['outbounds'])
            self.assertEqual(config.get('inbounds'), source.get('inbounds'))

    def test_happ_split_dns_in_every_profile(self):
        for config in json.loads(self.outputs['subscription.txt']):
            dns = config['dns']
            self.assertTrue(dns['disableFallbackIfMatch'])
            domestic = dns['servers'][:2]
            self.assertEqual([s['address'] for s in domestic],
                             ['tcp+local://77.88.8.8', 'tcp+local://77.88.8.1'])
            for server in domestic:
                self.assertTrue(server['skipFallback'])
                self.assertEqual(server['domains'], config['routing']['rules'][2]['domain'])
                for name in ('tbank.ru', 'sberbank.ru', 'ozon.ru', 'max.ru'):
                    self.assertIn('domain:' + name, server['domains'])
                self.assertNotIn('geosite:telegram', server['domains'])
            self.assertEqual(dns['servers'][2:],
                             ['https://8.8.8.8/dns-query', 'https://8.8.4.4/dns-query'])

    def test_all_karing_conversions_fail_preserves_previous_file(self):
        with patch.object(clients, 'connection', side_effect=ValueError('unsupported')):
            outputs = clients.build()
        self.assertEqual(outputs['subscription.txt'], self.outputs['subscription.txt'])
        self.assertEqual(outputs['subscription_karing.txt'],
                         (clients.ROOT / 'subscription_karing.txt').read_text())
        self.assertIn('previous subscription retained',
                      json.loads(outputs['build_report.json'])['karing_publication'])


if __name__ == '__main__':
    unittest.main()
