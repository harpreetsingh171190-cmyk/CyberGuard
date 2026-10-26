import unittest
from campaign_clustering import cluster_indicators

class CampaignClusteringTests(unittest.TestCase):
    def test_counts_repeated_hosts(self):
        result = cluster_indicators(["https://example.com/a", "https://example.com/b", "https://other.org/a"])
        self.assertEqual(result["indicator_count"], 3)
        self.assertEqual(result["unique_host_count"], 2)
        self.assertEqual(next(x["url_count"] for x in result["hosts"] if x["host"] == "example.com"), 2)

    def test_similar_hostnames(self):
        result = cluster_indicators(["https://paypa1.com/login", "https://paypal.com/login"])
        self.assertTrue(result["similar_hostname_pairs"])

    def test_shared_path_prefix(self):
        result = cluster_indicators(["https://a.example/login/x", "https://b.example/login/y"])
        self.assertTrue(any(x["path_prefix"] == "login" for x in result["shared_path_prefix_groups"]))

    def test_threshold_validation(self):
        with self.assertRaises(ValueError): cluster_indicators([], 0.2)

if __name__ == "__main__": unittest.main()
