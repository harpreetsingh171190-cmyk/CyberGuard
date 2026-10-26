import unittest
from analyst_report import build_case_report

class AnalystReportTests(unittest.TestCase):
    def test_report_contains_case_fields(self):
        html = build_case_report({'case_id':'CG-1','title':'Phishing case','severity':'High','status':'Investigating','indicators':['https://example.test/a'],'notes':'Review mailbox','timeline':[{'at':'2026-01-01','event':'Case created'}]})
        for value in ('CG-1','Phishing case','Investigating','https://example.test/a','Review mailbox','Case created'):
            self.assertIn(value, html)
        self.assertIn('window.print()', html)

    def test_user_content_is_escaped(self):
        html = build_case_report({'title':'<script>alert(1)</script>','notes':'<img src=x onerror=alert(1)>','indicators':['<svg onload=alert(1)>']})
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertNotIn('<img src=x', html)
        self.assertNotIn('<svg onload=', html)
        self.assertIn('&lt;script&gt;', html)

if __name__ == '__main__':
    unittest.main()
