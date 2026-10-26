import unittest
from url_heuristics import analyze_url

class URLHeuristicTests(unittest.TestCase):
    def test_https_normal_domain_low(self):
        self.assertLess(analyze_url('https://example.com/about')['score'], 25)
    def test_http_and_ip_raise_score(self):
        result = analyze_url('http://192.0.2.10:8080/login')
        self.assertGreaterEqual(result['score'], 35)
        self.assertTrue(result['findings'])
    def test_punycode_flagged(self):
        result = analyze_url('https://xn--e1afmkfd.example/')
        self.assertTrue(any('punycode' in x['indicator'].lower() for x in result['findings']))
    def test_substring_suffix_not_used_as_shortener(self):
        result = analyze_url('https://bit.ly.attacker.example/')
        self.assertFalse(any('shortening domain' in x['indicator'] for x in result['findings']))

if __name__ == '__main__': unittest.main()
