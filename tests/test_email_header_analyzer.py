import unittest
from email_header_analyzer import analyze_email_headers

class EmailHeaderTests(unittest.TestCase):
    def test_reply_to_mismatch_and_auth_fail(self):
        result = analyze_email_headers('From: Billing <billing@example.com>\nReply-To: thief@other.test\nAuthentication-Results: mx.test; spf=fail; dkim=pass; dmarc=fail\nReceived: by mx.test\n\n')
        codes = {x['code'] for x in result['findings']}
        self.assertIn('REPLY_TO_DOMAIN_MISMATCH', codes)
        self.assertIn('SPF_FAIL', codes)
        self.assertIn('DMARC_FAIL', codes)
        self.assertEqual(result['highest_severity'], 'high')
    def test_missing_auth_results_is_not_crash(self):
        result = analyze_email_headers('From: person@example.com\n\n')
        self.assertIn('NO_AUTH_RESULTS', {x['code'] for x in result['findings']})
    def test_empty_input(self):
        result = analyze_email_headers('')
        self.assertGreaterEqual(result['finding_count'], 1)
    def test_bounded_input(self):
        result = analyze_email_headers('X-Test: ' + 'a' * 250000)
        self.assertIsInstance(result['findings'], list)

if __name__ == '__main__': unittest.main()
