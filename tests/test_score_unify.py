"""Merged policy: centralized source scores and evidence-based outbound scores."""
import unittest
from gigang.engine import policy as P
from gigang.schemas.incident import Severity
class ScoreIntegrationTests(unittest.TestCase):
    def test_central_source_formula(self):
        p=P.load_policy()
        result=P.Judgment("WATCH",["CS-3"],[],kind="not_allowed")
        self.assertEqual(P.score_judgment(result,{"rrn":3},None,False,p).score,77)
        self.assertEqual(P.compute_score("not_allowed","WATCH",p["score"],{"rrn":3})[0],77)
    def test_no_critical_enum(self):
        self.assertNotIn("CRITICAL",Severity.__members__)
