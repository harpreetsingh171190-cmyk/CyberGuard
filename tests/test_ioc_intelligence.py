import unittest
from ioc_intelligence import cluster_indicators, to_stix_bundle

class IOCIntelligenceTests(unittest.TestCase):
    def test_cluster_groups_same_domain_and_sorts(self):
        rows = [
            {'value': 'https://a.example.com/login', 'heuristic_score': 25},
            {'value': 'https://b.example.com/update', 'heuristic_score': 55},
            {'value': 'https://other.net/x', 'heuristic_score': 5},
        ]
        groups = cluster_indicators(rows)
        self.assertEqual(groups[0]['group'], 'example.com')
        self.assertEqual(groups[0]['count'], 2)
        self.assertEqual(groups[0]['max_risk'], 55)

    def test_stix_bundle_shape_and_safe_pattern(self):
        bundle = to_stix_bundle([{'value': "https://example.com/a'b", 'heuristic_score': 60, 'heuristic_level': 'High'}])
        self.assertEqual(bundle['type'], 'bundle')
        obj = bundle['objects'][0]
        self.assertEqual(obj['type'], 'indicator')
        self.assertIn("\\'", obj['pattern'])
        self.assertIn('not assert maliciousness', obj['description'])

    def test_empty_bundle(self):
        self.assertEqual(to_stix_bundle([])['objects'], [])

if __name__ == '__main__': unittest.main()
