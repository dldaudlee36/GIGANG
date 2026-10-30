import ast
import base64
import json
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from gigang.engine import policy as P
from gigang.schemas.event import EventAction
from test_outbound_scoring import engine, event

AGENT = Path(__file__).resolve().parents[1] / 'guard' / 'agent'
sys.path.insert(0, str(AGENT))
from portal_inspection import inspect_content, metadata

class PortalTests(unittest.TestCase):
    def setUp(self):
        self.policy=P.load_policy()
        self.policy['users']={'audit':'CS','hr':'HR'}
    def portal(self, kind='COPY_ATTEMPT', hits=None, user='audit', inspectable=True, prior=None):
        return P.judge_portal(kind,user,{'pattern_hits':hits or {},'inspectable':inspectable},self.policy,prior)
    def test_allowed_small_copy_is_record(self):
        r=self.portal(hits={'email':1})
        self.assertEqual((r.level,r.score),('RECORD',29))
    def test_sensitive_copy_uses_formula(self):
        r=self.portal(hits={'rrn_high':3})
        self.assertEqual((r.level,r.score),('WATCH',77))
    def test_download_adds_five_not_fixed_seventy(self):
        r=self.portal('DOWNLOAD_STARTED',{'rrn_high':3})
        self.assertEqual(r.score,82)
    def test_larger_counts_raise_score(self):
        self.assertGreater(self.portal(hits={'rrn_high':30}).score,self.portal(hits={'rrn_high':1}).score)
    def test_capture_uses_ocr_sensitivity(self):
        self.assertEqual(self.portal('DB_IMAGE_CAPTURE',{'rrn_high':3}).score,77)
        self.assertEqual(self.portal('DB_IMAGE_CAPTURE',{'email':1}).score,64)
    def test_missing_inspection_is_not_zero_hits(self):
        r=self.portal(inspectable=False)
        self.assertEqual((r.level,r.score),('WATCH',62))
        self.assertIn('검사 불가',r.reasons[0])
    def test_repeated_small_copies_accumulate_counts(self):
        r=self.portal(hits={'phone':4},prior={'phone':8})
        self.assertEqual((r.level,r.score),('WATCH',69))
    def run_event(self,e,ev):
        with patch('gigang.engine.correlation.on_risk_state_changed'): e.update_user_risk(ev)
    def test_real_portal_event_no_ai_log_required(self):
        e=engine();e.policy=self.policy;e.user_db_counts={}
        ev=event(EventAction.COPY_ATTEMPT,target='desktop-oli.tail2bbbea.ts.net',extra={
            'source_path':'/db','detection_scope':'customer_table','inspectable':True,'pattern_hits':{'rrn_high':3},'text_length':100})
        self.run_event(e,ev)
        self.assertEqual(e.store.risk['score'],77)
    def test_weak_new_event_cannot_lower_existing_watch(self):
        e=engine('WATCH',83);self.run_event(e,event())
        self.assertEqual(e.store.risk['score'],83)
    def test_completed_download_does_not_score_again(self):
        e=engine('WATCH',82);e.user_db_counts={}
        self.run_event(e,event(EventAction.DOWNLOAD_COMPLETED,target='desktop-oli.tail2bbbea.ts.net',name='a.csv',size=2,extra={'source_path':'/db/download'}))
        self.assertEqual(e.store.risk['score'],82)
        self.assertEqual(len(e.user_db_downloads['audit']),1)
        self.assertEqual(e.user_db_counts,{})
    def test_portal_mode_skips_duplicate_clipboard_event(self):
        e=engine('WATCH',77)
        self.run_event(e,event(EventAction.CLIPBOARD_COPY,target='desktop-oli.tail2bbbea.ts.net',extra={'pattern_hits':{'rrn_high':3}}))
        self.assertEqual(e.store.risk['score'],77)
        self.assertFalse(e.store.history)
    def test_outbound_inherits_actual_counts_and_reaches_expected_score(self):
        e=engine('WATCH',77)
        from test_outbound_scoring import matched
        self.run_event(e,event(extra=matched({'rrn_high':3})))
        self.assertEqual((e.store.risk['state'],e.store.risk['score']),('HIGH',87))
    def test_watch_source_is_saved_as_individual_incident(self):
        e=engine();e.policy=self.policy;e.user_db_counts={}
        ev=event(EventAction.COPY_ATTEMPT,target='desktop-oli.tail2bbbea.ts.net',extra={
            'source_path':'/db','detection_scope':'customer_table','inspectable':True,'pattern_hits':{'rrn_high':3}})
        self.run_event(e,ev)
        self.assertEqual(e.store.incidents[0].score,77)
        self.assertEqual(e.store.incidents[0].severity.value,'MEDIUM')
    def test_lower_event_keeps_own_score_and_user_summary(self):
        e=engine('WATCH',83);self.run_event(e,event())
        self.assertEqual(e.store.incidents[0].score,40)
        self.assertEqual(e.store.risk['score'],83)
    def test_duplicate_event_does_not_rescore(self):
        e=engine();e.policy=self.policy;e.user_db_counts={}
        ev=event(EventAction.COPY_ATTEMPT,target='desktop-oli.tail2bbbea.ts.net',extra={
            'source_path':'/db','detection_scope':'customer_table','inspectable':True,'pattern_hits':{'rrn_high':3}})
        self.run_event(e,ev);self.run_event(e,ev)
        self.assertEqual(len(e.store.incidents),1)
        self.assertEqual(len(e.user_db_counts['audit']),1)
    def test_local_text_scanner_returns_only_metadata(self):
        r=inspect_content({'text':'고객 이메일 alice@example.com bob@example.com'})
        self.assertEqual(r['pattern_hits']['email'],2)
        self.assertNotIn('alice',json.dumps(r))
    def test_local_file_scanner(self):
        r=inspect_content({'file_name':'a.csv','file_base64':base64.b64encode(b'alice@example.com').decode()})
        self.assertTrue(r['inspectable'])
        self.assertEqual(r['pattern_hits']['email'],1)
    def test_unsupported_file_is_explicitly_uninspectable(self):
        r=inspect_content({'file_name':'a.pdf','file_base64':base64.b64encode(b'%PDF').decode()})
        self.assertFalse(r['inspectable'])
    def test_metadata_rejects_invalid_counts(self):
        with self.assertRaises(ValueError):metadata({'pattern_hits':{'email':-1}})
        with self.assertRaises(ValueError):metadata({'pattern_hits':{'email':True}})
    def test_agent_copy_and_download_preserve_metadata(self):
        # Execute the actual receiver functions without importing Windows-only background services.
        tree=ast.parse((AGENT/'agent.py').read_text(encoding='utf-8'))
        funcs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('extension_event','download_event')]
        scope={'base_event':lambda k,t:{'event_type':k,'target':t},'inspection_metadata':metadata,
               'attach_authorization':lambda *a:None,'add_client_time':lambda *a:None,'link_metadata':lambda *a:{},'DOWNLOADED':{}}
        exec(compile(ast.Module(body=funcs,type_ignores=[]),'agent.py','exec'),scope)
        data={'target':'desktop-oli.tail2bbbea.ts.net','source_path':'/db','detection_scope':'customer_table',
              'inspectable':True,'pattern_hits':{'email':2},'text_length':30}
        copy=scope['extension_event']('/copy-event',data)
        self.assertEqual(copy['event_type'],'COPY_ATTEMPT')
        self.assertEqual(copy['pattern_hits']['email'],2)
        dl=scope['download_event']({**data,'source_path':'/db/download','event_type':'DOWNLOAD_STARTED','file_name':'a.csv','file_size':30})
        self.assertEqual(dl['pattern_hits']['email'],2)
    def test_collector_preserves_raw_inspection(self):
        from gigang.collectors import team_collector as tc
        raw={'source_path':'/db','detection_scope':'customer_table','inspectable':True,'pattern_hits':{'rrn_high':3},'text_length':40}
        row={'id':999,'event_time':'2026-10-29 12:00:00','user_name':'audit','event_type':'COPY_ATTEMPT',
             'target':'desktop-oli.tail2bbbea.ts.net','source':'chrome-extension','raw_data':json.dumps(raw)}
        with patch.object(tc,'fetch_railway_events',return_value=[row]),patch.object(tc,'fetch_remote_db_logs',return_value=[]),patch.object(tc,'fetch_activity_log_events',return_value=[]):
            events=tc.get_team_security_events()
        self.assertEqual(events[0].payload.extra['pattern_hits']['rrn_high'],3)
        self.assertTrue(events[0].payload.extra['inspectable'])

if __name__=='__main__':unittest.main()
