import unittest
from content_signatures import scan_content

class ContentSignatureTests(unittest.TestCase):
    def test_detects_encoded_powershell(self):
        r=scan_content('sample.txt', b'powershell.exe -EncodedCommand SQBFAFgA')
        self.assertTrue(any(x['id']=='PS_ENCODED_COMMAND' for x in r['findings']))
    def test_clean_text(self):
        r=scan_content('notes.txt', b'hello world')
        self.assertEqual(r['finding_count'], 0)
        self.assertEqual(r['highest_severity'], 'info')
    def test_scan_is_bounded(self):
        r=scan_content('large.bin', b'A'*(2*1024*1024+1))
        self.assertTrue(r['truncated'])
        self.assertEqual(r['bytes_scanned'], 2*1024*1024)
    def test_custom_signature(self):
        r=scan_content('a.txt', b'ALERT-123', [{'id':'CUSTOM1','pattern':'ALERT-\\d+','severity':'low','description':'test'}])
        self.assertEqual(r['finding_count'],1)

if __name__ == '__main__': unittest.main()
