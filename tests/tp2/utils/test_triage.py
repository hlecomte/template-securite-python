import unittest
from src.tp2.utils.triage import Triage

class MyTestCase(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)  # add assertion here


if __name__ == '__main__':
    unittest.main()

def test_init_Triage():

    # Given
    path = "/home/hlecomte/PycharmProjects/template-securite-python/src/tp2/suspectfile"
    rules = "/home/hlecomte/PycharmProjects/template-securite-python/src/tp2/rules"
    out = "/home/hlecomte/PycharmProjects/template-securite-python/src/tp2/report"
    llm = "opensearch"


    # When
    triage = Triage(path, rules, out, llm)

    # Then
    assert triage.path == path
    assert triage.rules_path == rules
    assert triage.out_path == out
    assert triage.backend == llm

