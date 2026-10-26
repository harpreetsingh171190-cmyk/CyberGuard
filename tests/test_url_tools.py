import unittest
from url_tools import defang_url, normalize_url, url_facts, url_fingerprint, extract_urls

class URLToolsTests(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(defang_url('https://evil.example/login'), 'hxxps://evil[.]example/login')
    def test_normalize_default_port_and_fragment(self):
        self.assertEqual(normalize_url('HTTPS://Example.COM:443/a#frag'), 'https://example.com/a')
    def test_normalize_rejects_missing_host(self):
        with self.assertRaises(ValueError): normalize_url('not-a-url')
    def test_fingerprint_is_stable_and_sha256_length(self):
        self.assertEqual(url_fingerprint("https://example.com"), url_fingerprint("https://example.com"))
        self.assertEqual(len(url_fingerprint("https://example.com")), 64)
    def test_extract_urls_deduplicates_and_trims_punctuation(self):
        self.assertEqual(extract_urls("Visit https://example.com/a, then https://example.com/a!"), ["https://example.com/a"])
    def test_facts(self):
        facts = url_facts('https://a.b.example.com/a/b?x=1&y=2#f')
        self.assertEqual(facts['subdomain_count'], 2)
        self.assertEqual(facts['path_depth'], 2)
        self.assertEqual(facts['query_parameter_count'], 2)

if __name__ == '__main__': unittest.main()
