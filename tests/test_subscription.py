import copy
import html
import json
import os
import unittest
from unittest.mock import patch

from scripts import refresh_subscription as sub


class SubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.catalog = sub.load_json(sub.CATALOG_PATH)
        self.domains = sub.current_direct_domains(self.catalog)

    def test_published_catalog(self):
        sub.validate(self.catalog, len(self.catalog), self.domains)
        self.assertTrue(self.catalog)
        self.assertEqual(len(self.catalog), len(sub.deduplicate_configs(self.catalog)))

    def test_json_roundtrip(self):
        self.assertEqual(sub.extract_configs(json.dumps(self.catalog)), self.catalog)

    def test_html_source(self):
        entry = self.catalog[1]
        source = '<div data-config="' + html.escape(json.dumps(entry), quote=True) + '"></div>'
        self.assertEqual(sub.extract_configs(source), [entry])

    def test_invalid_sources(self):
        for source in ('[]', 'null', '<html>Error</html>', '{}'):
            with self.subTest(source=source), self.assertRaises(RuntimeError):
                sub.extract_configs(source)

    def test_empty_catalog_rejected(self):
        with self.assertRaises(RuntimeError):
            sub.validate([], 0, self.domains)

    def test_suspicious_catalog_shrink_rejected(self):
        previous_count = max(10, len(self.catalog))
        tiny = copy.deepcopy(self.catalog[:2])
        with self.assertRaisesRegex(RuntimeError, 'suspicious catalog shrink'):
            sub.validate(tiny, len(tiny), self.domains, previous_count)

    def test_normalization_idempotent(self):
        catalog = copy.deepcopy(self.catalog)
        for entry in catalog:
            sub.normalize_direct(entry, self.domains)
        once = copy.deepcopy(catalog)
        for entry in catalog:
            sub.normalize_direct(entry, self.domains)
        self.assertEqual(catalog, once)
        sub.validate(catalog, len(catalog), self.domains)

    def test_no_default_network_source(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(sub.urllib.request, 'urlopen') as fetch:
            with self.assertRaises(RuntimeError):
                sub.fetch_subscription_text()
            fetch.assert_not_called()

    def test_local_source(self):
        with patch.dict(os.environ, {'SUBSCRIPTION_SOURCE_FILE': str(sub.CATALOG_PATH)}, clear=True):
            self.assertEqual(json.loads(sub.fetch_subscription_text()), self.catalog)

    def test_deduplication_uses_latest(self):
        first = {'remarks': 'same', 'value': 1}
        last = {'remarks': 'same', 'value': 2}
        self.assertEqual(sub.deduplicate_configs([first, last]), [last])


if __name__ == '__main__':
    unittest.main()
