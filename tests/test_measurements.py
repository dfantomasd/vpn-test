import json
import subprocess
import unittest
from unittest.mock import patch

from scripts import build_clients as clients
from scripts import measure_nodes as measure


class MeasurementTests(unittest.TestCase):
    def test_curl_uses_proxy_and_bounded_download(self):
        response = subprocess.CompletedProcess([], 0, json.dumps({'http_code': 204}), '')
        with patch.object(measure.subprocess, 'run', return_value=response) as run:
            result = measure.curl_probe(12345, measure.PING_URL, 4096)
        args = run.call_args.args[0]
        self.assertIn('socks5h://127.0.0.1:12345', args)
        self.assertIn('--max-filesize', args)
        self.assertIn('--max-time', args)
        self.assertEqual(result['http_code'], 204)

    def test_failed_curl_not_success(self):
        response = subprocess.CompletedProcess([], 28, '', 'timeout')
        with patch.object(measure.subprocess, 'run', return_value=response):
            result = measure.curl_probe(12345, measure.PING_URL, 4096)
        self.assertEqual(result['curl_exit'], 28)

    def test_ranking_uses_metrics_and_marks_vantage(self):
        first = {'protocol': 'vless', 'settings': {'test': 1}}
        second = {'protocol': 'vless', 'settings': {'test': 2}}
        metrics = {'measured_at': '2026-09-04T00:00:00+00:00', 'nodes': {
            clients.node_key(first): {'status': 'ok', 'speed_mbps': 1, 'latency_ms': 500},
            clients.node_key(second): {'status': 'ok', 'speed_mbps': 10, 'latency_ms': 50},
        }}
        with patch.object(clients.Path, 'exists', return_value=True), patch.object(clients, 'read_json', return_value=metrics):
            result = clients.ranked_nodes([('first', first), ('second', second)], '2026-09-04T01:00:00+00:00')
        self.assertIs(result[0][1], second)
        self.assertIn('тест GitHub', result[0][0])
        self.assertIn('10.00 Мбит/с', result[0][0])
        self.assertIn('50 мс', result[0][0])

    def test_unmeasured_never_invents_speed(self):
        with patch.object(clients.Path, 'exists', return_value=False):
            ranked = clients.ranked_nodes([('sample', {'protocol': 'vless'})])
        self.assertIn('нет замера', ranked[0][0])
        self.assertNotIn('Мбит/с', ranked[0][0])

    def test_stale_karing_measurements_not_ranked_or_labeled(self):
        first, second = {'id': 1}, {'id': 2}
        report = {'measured_at': '2026-09-04T00:00:00+00:00', 'nodes': {
            clients.node_key(second): {'status': 'ok', 'speed_mbps': 100, 'latency_ms': 1}}}
        with patch.object(clients.Path, 'exists', return_value=True), \
                patch.object(clients, 'read_json', return_value=report):
            result = clients.ranked_nodes([('first', first), ('second', second)], '2026-09-04T07:00:00+00:00')
        self.assertIs(result[0][1], first)
        self.assertTrue(all('Мбит/с' not in name for name, _ in result))

    def test_unsupported_measurement_does_not_start_core(self):
        with patch.object(clients, 'connection', side_effect=ValueError('unsupported')), \
                patch.object(measure.subprocess, 'Popen') as start:
            _, result = measure.measure(('test', {'protocol': 'vless'}), 'unused')
        self.assertEqual(result['reason'], 'unsupported_conversion')
        start.assert_not_called()
