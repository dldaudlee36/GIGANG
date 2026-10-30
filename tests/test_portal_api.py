import json
import sys
import threading
import unittest
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4
import requests

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'guard'/'agent'))
import agent

class PortalApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events=[]
        cls.patcher=patch.object(agent,'send_to_railway',side_effect=lambda e: cls.events.append(e) is None)
        cls.patcher.start()
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),agent.ExtensionEventHandler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'
        cls.headers={'Origin':'chrome-extension://'+'a'*32}
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.patcher.stop()
    def post(self,path,data,headers=None):
        return requests.post(self.base+path,json=data,headers=headers or self.headers,timeout=10)
    def test_raw_text_inspection_stays_local(self):
        n=len(self.events)
        r=self.post('/inspect-content',{'text':'alice@example.com bob@example.com'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['pattern_hits']['email'],2)
        self.assertEqual(len(self.events),n)
        self.assertNotIn('alice',r.text)
    def test_inspection_rejects_web_origin(self):
        self.assertEqual(self.post('/inspect-content',{'text':'x'},{'Origin':'https://example.com'}).status_code,403)
    def test_copy_route_forwards_counts_not_plaintext(self):
        r=self.post('/copy-event',{'target':'desktop-oli.tail2bbbea.ts.net','source_path':'/db',
            'detection_scope':'customer_table','trace_id':str(uuid4()),'timestamp':datetime.now(timezone.utc).isoformat(),
            'match_status':'source_recorded','inspectable':True,'pattern_hits':{'email':2},'text_length':100,
            'text':'must-not-leave-local'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.events[-1]['event_type'],'COPY_ATTEMPT')
        self.assertEqual(self.events[-1]['pattern_hits']['email'],2)
        self.assertNotIn('must-not-leave-local',json.dumps(self.events[-1]))
    def test_download_route_accepts_new_browser_format(self):
        r=self.post('/download-event',{'target':'desktop-oli.tail2bbbea.ts.net','source_path':'/db/download',
            'event_type':'DOWNLOAD_STARTED','download_id':1,'download_state':'in_progress',
            'trace_id':str(uuid4()),'timestamp':datetime.now(timezone.utc).isoformat(),
            'file_name':'customers.csv','file_size':100,'inspectable':True,'pattern_hits':{'email':3}})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.events[-1]['event_type'],'DOWNLOAD_STARTED')
        self.assertEqual(self.events[-1]['pattern_hits']['email'],3)
    def test_ocr_counts_return_for_image_risk(self):
        with patch.object(agent,'recognize_image',return_value={'status':'ok','lines':['alice@example.com']}):
            r=self.post('/image-ocr',{})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['inspection']['pattern_hits']['email'],1)
    def test_bad_counts_not_forwarded(self):
        n=len(self.events)
        r=self.post('/copy-event',{'target':'desktop-oli.tail2bbbea.ts.net','source_path':'/db',
            'detection_scope':'customer_table','pattern_hits':{'email':-1}})
        self.assertEqual(r.status_code,400,r.text)
        self.assertEqual(len(self.events),n)

if __name__=='__main__':unittest.main()
