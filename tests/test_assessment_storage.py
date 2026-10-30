import gc
import tempfile
import unittest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch
from gigang.storage.sqlite_store import SQLiteStore
from gigang.schemas.event import EventAction
from test_outbound_scoring import engine,event
from gigang.engine import policy as P

class AssessmentStorageTests(unittest.TestCase):
    def test_source_and_outbound_scores_persist_independently(self):
        with tempfile.TemporaryDirectory() as folder:
            e=engine();e.store=SQLiteStore(str(Path(folder)/'test.db'))
            e.policy=P.load_policy();e.policy['users']={'audit':'CS'};e.user_db_counts={}
            source=event(EventAction.COPY_ATTEMPT,target='desktop-oli.tail2bbbea.ts.net',extra={
                'source_path':'/db','detection_scope':'customer_table','inspectable':True,'pattern_hits':{'rrn_high':3}})
            source.event_id='copy-1'
            unrelated=event();unrelated.event_id='paste-1'
            with patch('gigang.engine.correlation.on_risk_state_changed'):
                e.update_user_risk(source);e.update_user_risk(unrelated)
            saved={i.event_ids[0]:i.score for i in e.store.get_all_incidents()}
            self.assertEqual(saved,{'copy-1':77,'paste-1':40})
            self.assertEqual(e.store.get_active_risk('audit')['score'],77)
            # Reconstruct cached incidents as startup does; replay must not count the source again.
            e.incidents={i.incident_id:i for i in e.store.get_all_incidents()}
            e.update_user_risk(source)
            self.assertEqual(len(e.store.get_all_incidents()),2)
            del e
            gc.collect()

if __name__=='__main__':unittest.main()
