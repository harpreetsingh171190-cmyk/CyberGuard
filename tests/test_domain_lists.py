import tempfile, unittest
from domain_lists import match_domain

class DomainListTests(unittest.TestCase):
    def test_exact_and_subdomain_block(self):
        lists={"allow":[],"block":["bad.example"]}
        self.assertEqual(match_domain("https://bad.example/path",lists),("block","bad.example"))
        self.assertEqual(match_domain("https://sub.bad.example",lists),("block","bad.example"))
    def test_suffix_attack_does_not_match(self):
        self.assertEqual(match_domain("https://notbad.example",{"allow":[],"block":["bad.example"]}),("", ""))
    def test_block_precedes_allow(self):
        self.assertEqual(match_domain("https://bad.example",{"allow":["bad.example"],"block":["bad.example"]})[0],"block")

if __name__ == "__main__": unittest.main()
