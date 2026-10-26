import unittest
from cyberguard_reputation import _validate_url, check_live_reputation

class URLValidationTests(unittest.TestCase):
    def test_accepts_http_https(self):
        self.assertEqual(_validate_url("https://example.com"), "https://example.com")
    def test_rejects_scheme_relative(self):
        with self.assertRaises(ValueError): _validate_url("//example.com")
    def test_rejects_ftp(self):
        with self.assertRaises(ValueError): _validate_url("ftp://example.com")
    def test_rejects_credentials(self):
        with self.assertRaises(ValueError): _validate_url("https://user:pass@example.com")
    def test_rejects_empty_and_oversize(self):
        for value in ("", "x"*2049):
            with self.assertRaises(ValueError): _validate_url(value)

if __name__ == "__main__": unittest.main()
