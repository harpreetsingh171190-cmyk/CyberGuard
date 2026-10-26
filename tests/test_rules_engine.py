import unittest
from rules_engine import DEFAULT_RULES, scan_text, validate_rules

class RuleEngineTests(unittest.TestCase):
    def test_default_rule_matches_case_insensitive(self):
        r = scan_text('Please VERIFY YOUR PASSWORD now')
        self.assertEqual(r['max_severity'], 'high')
        self.assertTrue(any(x['rule_id'] == 'AUTH-001' for x in r['findings']))
    def test_custom_literal_rule(self):
        r = scan_text('abc xyz abc', [{'id':'T1','name':'test','pattern':'abc','severity':'critical'}])
        self.assertEqual(r['findings'][0]['match_count'], 2)
        self.assertEqual(r['max_severity'], 'critical')
    def test_no_match(self):
        self.assertEqual(scan_text('ordinary text')['matched_rules'], 0)
    def test_duplicate_id_rejected(self):
        with self.assertRaises(ValueError):
            validate_rules([{'id':'x','pattern':'a'},{'id':'x','pattern':'b'}])
    def test_invalid_severity_rejected(self):
        with self.assertRaises(ValueError): validate_rules([{'id':'x','pattern':'a','severity':'urgent'}])
    def test_input_is_bounded(self):
        r = scan_text('x' * 1_000_010, [])
        self.assertEqual(r['text_characters_scanned'], 1_000_000)

if __name__ == '__main__': unittest.main()
