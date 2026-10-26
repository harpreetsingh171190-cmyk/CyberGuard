import tempfile
import unittest
from pathlib import Path
from casebook import create_case, load_cases, update_case, delete_case

class CasebookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'cases.json'
    def tearDown(self): self.tmp.cleanup()
    def test_create_update_timeline_and_delete(self):
        c = create_case(' Phishing review ', 'High', ['https://a.example', 'https://a.example'], 'Investigate', self.path)
        self.assertEqual(c['title'], 'Phishing review')
        self.assertEqual(len(c['indicators']), 1)
        updated = update_case(c['case_id'], status='Investigating', notes='Reviewed', path=self.path)
        self.assertEqual(updated['status'], 'Investigating')
        self.assertGreaterEqual(len(updated['timeline']), 3)
        delete_case(c['case_id'], self.path)
        self.assertEqual(load_cases(self.path), [])
    def test_validation(self):
        with self.assertRaises(ValueError): create_case('', path=self.path)
        c = create_case('Test', path=self.path)
        with self.assertRaises(ValueError): update_case(c['case_id'], status='Unknown', path=self.path)

if __name__ == '__main__': unittest.main()
