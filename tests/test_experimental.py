import unittest
from scripts.experimental_vless import parse_link


class ExperimentalTests(unittest.TestCase):
    def link(self, host='1.1.1.1', params='security=tls&type=tcp&sni=example.com'):
        return f'vless://00000000-0000-0000-0000-000000000001@{host}:443?{params}'

    def test_tls_credentials_preserved(self):
        outbound = parse_link(self.link())
        self.assertEqual(outbound['settings']['vnext'][0]['address'], '1.1.1.1')
        self.assertEqual(outbound['streamSettings']['tlsSettings']['serverName'], 'example.com')

    def test_reality_parameters_preserved(self):
        outbound = parse_link(self.link(params='security=reality&type=tcp&sni=example.com&pbk=' +
                                       'a' * 43 + '&sid=abcd&flow=xtls-rprx-vision&spx=%2Fhello'))
        self.assertEqual(outbound['streamSettings']['realitySettings']['shortId'], 'abcd')
        self.assertEqual(outbound['streamSettings']['realitySettings']['spiderX'], '/hello')

    def test_private_local_and_hostname_rejected(self):
        for host in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '[::1]', 'example.com'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                parse_link(self.link(host))

    def test_unknown_duplicate_or_insecure_parameters_rejected(self):
        for extra in ('&allowInsecure=1', '&insecure=true', '&type=ws', '&unknown=yes'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                parse_link(self.link() + extra)

    def test_unencrypted_transport_rejected(self):
        with self.assertRaises(ValueError):
            parse_link(self.link(params='security=none&type=tcp'))

    def test_russian_label_rejected(self):
        with self.assertRaises(ValueError):
            parse_link(self.link() + '#RU server')

    def test_other_protocol_rejected(self):
        with self.assertRaises(ValueError):
            parse_link(self.link().replace('vless://', 'vmess://'))
