import unittest
from file_triage import analyze_file_bytes

class FileTriageTests(unittest.TestCase):
    def test_hash_and_size(self):
        r=analyze_file_bytes('hello.txt', b'hello')
        self.assertEqual(r['size_bytes'], 5)
        self.assertEqual(r['sha256'], '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
    def test_signature_extension_mismatch(self):
        r=analyze_file_bytes('invoice.pdf', b'MZ' + b'0'*50)
        self.assertIn('EXTENSION_MISMATCH', [x['code'] for x in r['findings']])
    def test_double_extension(self):
        r=analyze_file_bytes('report.exe.pdf', b'%PDF-1.7')
        self.assertIn('DOUBLE_EXTENSION', [x['code'] for x in r['findings']])
    def test_empty_file(self):
        self.assertEqual(analyze_file_bytes('empty.bin', b'')['highest_severity'], 'low')
    def test_does_not_execute_content(self):
        r=analyze_file_bytes('x.txt', b'print("hello")')
        self.assertEqual(r['size_bytes'], 14)

if __name__ == '__main__': unittest.main()
