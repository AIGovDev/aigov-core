import unittest
from benchmark import SCENARIOS, make_case, verify, run

class BenchmarkTests(unittest.TestCase):
    def test_all_scenarios(self):
        for name in SCENARIOS:
            with self.subTest(name=name):
                actual, _ = verify(make_case(name))
                self.assertEqual(actual, name == "authorized")

    def test_deterministic(self):
        self.assertEqual(run(), run())

    def test_mutation_detected(self):
        entries = make_case("authorized")
        entries[2]["payload"]["value"] = "changed"
        self.assertEqual(verify(entries)[1], "chain_integrity")

    def test_unknown_scenario(self):
        with self.assertRaises(ValueError):
            make_case("unknown")

if __name__ == "__main__":
    unittest.main()
