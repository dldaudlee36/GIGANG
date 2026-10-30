import unittest
from datetime import datetime, timedelta
from unittest.mock import patch
from gigang.engine import policy as P
from gigang.engine.correlation import CorrelationEngine
from gigang.schemas.event import SecurityEvent, LogSource, EventAction, Actor, Target, PayloadMetadata

class Store:
    def __init__(self, state="NORMAL", score=0):
        self.risk = {"state": state, "score": score}
        self.history, self.incidents = [], []
    def get_active_risk(self, user): return self.risk
    def upsert_risk(self, user, state, score, reasons, expiry):
        self.risk = {"state": state, "score": score, "reasons": reasons}
    def append_history(self, *args): self.history.append(args)
    def save_incident(self, inc): self.incidents.append(inc)
    def has_user_prior_watch_history(self, user): return True

def engine(state="NORMAL", score=0):
    e = CorrelationEngine.__new__(CorrelationEngine)
    e.policy = P.load_policy()
    e.store = Store(state, score)
    e.incidents, e._incident_seq = {}, {}
    e.user_db_downloads, e.user_db_copies = {}, {}
    return e

def event(action=EventAction.PASTE_ATTEMPT, target="chatgpt.com", extra=None, name=None, size=None):
    return SecurityEvent(event_id="test-event", timestamp=datetime.utcnow(),
        log_source=LogSource.CHROME_EXTENSION,
        actor=Actor(user_id="audit", src_ip="10.0.0.1"), target=Target(domain=target),
        action=action, payload=PayloadMetadata(extra=extra or {}, file_name=name, file_size=size))

def matched(hits=None, blocked=False):
    x = {"match_status":"matched", "match":{"source_domain":"desktop-oli.tail2bbbea.ts.net"},
         "pattern_hits":hits or {}}
    if blocked: x["image_guard"] = {"outcome":"blocked_match"}
    return x

class OutboundTests(unittest.TestCase):
    def run_event(self, e, ev):
        with patch("gigang.engine.correlation.on_risk_state_changed") as notify:
            e.update_user_risk(ev)
        return notify

    def test_prior_watch_history_does_not_escalate(self):
        e=engine(); self.run_event(e,event(EventAction.FILE_UPLOAD_ATTEMPT,name="photo.png",size=100))
        self.assertEqual(e.store.risk["state"],"NORMAL")
        self.assertLess(e.store.risk["score"],75)
        self.assertFalse(any(i.severity.value == "HIGH" for i in e.store.incidents))

    def test_watch_intranet_attachment_does_not_escalate(self):
        e=engine("WATCH",60)
        self.run_event(e,event(EventAction.FILE_UPLOAD_ATTEMPT,target="intranet.example",name="a.txt",size=1))
        self.assertEqual(e.store.risk["score"],60)
        self.assertFalse(any(i.severity.value == "HIGH" for i in e.store.incidents))

    def test_watch_paste_without_matching_content_stays_watch(self):
        e=engine("WATCH",60); self.run_event(e,event(extra={"text_length":3000}))
        self.assertEqual(e.store.risk["state"],"WATCH")
        self.assertNotEqual(e.store.risk["score"],93)

    def test_length_match_is_weak(self):
        e=engine(); e.user_db_copies["audit"]=[{"time":datetime.utcnow(),"length":200}]
        self.run_event(e,event(extra={"text_length":200}))
        self.assertEqual(e.store.risk["state"],"WATCH")
        self.assertFalse(any(i.severity.value == "HIGH" for i in e.store.incidents))

    def test_metadata_match_is_weak(self):
        e=engine(); e.user_db_downloads["audit"]=[{"name":"customers.xlsx","size":100}]
        self.run_event(e,event(EventAction.FILE_UPLOAD_ATTEMPT,name="customers.xlsx",size=100))
        self.assertEqual(e.store.risk["state"],"WATCH")
        self.assertFalse(any(i.severity.value == "HIGH" for i in e.store.incidents))

    def test_content_match_has_shared_incident_score(self):
        e=engine(); self.run_event(e,event(extra=matched({"rrn_high":3})))
        self.assertEqual(e.store.risk["state"],"HIGH")
        self.assertEqual(e.store.risk["score"],e.store.incidents[0].score)

    def test_stronger_evidence_increases_score(self):
        low,high=engine(),engine()
        self.run_event(low,event(extra=matched()))
        self.run_event(high,event(extra=matched({"rrn_high":30})))
        self.assertGreater(high.store.risk["score"],low.store.risk["score"])

    def test_blocked_match_is_not_completed_transmission(self):
        e=engine(); self.run_event(e,event(extra=matched(blocked=True)))
        self.assertIn("전송 전 차단"," ".join(e.store.risk["reasons"]))
        self.assertIn("전송 완료를 의미하지 않습니다",e.store.incidents[0].summary)

    def test_approved_destination(self):
        e=engine(); e.policy["approved_outbound_domains"]=["chatgpt.com"]
        self.run_event(e,event(extra=matched()))
        self.assertEqual(e.store.risk["state"],"NORMAL")

    def test_same_grade_updates_without_duplicate_notification(self):
        e=engine("HIGH",75)
        n=self.run_event(e,event(extra=matched({"rrn_high":30})))
        self.assertGreater(e.store.risk["score"],75)
        n.assert_not_called()
        self.assertTrue(e.store.history)

    def test_low_risk_event_preserves_existing_high(self):
        e=engine("HIGH",90); self.run_event(e,event())
        self.assertEqual(e.store.risk["score"],90)

    def test_high_scores_do_not_saturate_at_ten_records(self):
        ten,thirty=engine('WATCH',60),engine('WATCH',60)
        self.run_event(ten,event(extra=matched({'rrn_high':10})))
        self.run_event(thirty,event(extra=matched({'rrn_high':30})))
        self.assertEqual(ten.store.risk['score'],92)
        self.assertEqual(thirty.store.risk['score'],96)
    def test_exact_download_match_keeps_download_weight(self):
        e=engine('WATCH',60)
        extra=matched({'rrn_high':3});extra['match']['source_kind']='DOWNLOAD_COMPLETED'
        self.run_event(e,event(EventAction.FILE_UPLOAD_ATTEMPT,extra=extra,name='a.csv',size=100))
        self.assertEqual(e.store.risk['score'],92)
    def test_legacy_judges_use_shared_scoring(self):
        p=P.load_policy(); now=datetime.utcnow()
        u=P.judge_upload("a",1,"chatgpt.com",None,[{"name":"a","size":1,"source":"db","time":now}],p["score"])
        c=P.judge_paste_after_copy([{"time":now,"length":20,"source":"db"}],now,20,"chatgpt.com",p)
        self.assertEqual(u.level,"WATCH")
        self.assertEqual(c.level,"WATCH")

if __name__ == "__main__": unittest.main()
