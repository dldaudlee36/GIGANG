import base64
import json
from pathlib import Path
import sys
import threading
import unittest
from datetime import datetime, timezone
from uuid import uuid4
from http.server import ThreadingHTTPServer
import requests

root=Path(__file__).parent
sys.path.insert(0,str(root.parent.parent/'guard/agent'))
import agent
from image_ocr import recognize_image

class ImageApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events=[]
        agent.send_to_railway=lambda event: cls.events.append(event) is None
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),agent.ExtensionEventHandler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.url=f'http://127.0.0.1:{cls.server.server_port}'
        cls.headers={'Origin':'chrome-extension://'+'a'*32}
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def test_origin_rejected(self):
        for origin in ('https://evil.invalid','null',''):
            self.assertEqual(requests.post(self.url+'/image-ocr',json={},headers={'Origin':origin}).status_code,403)
    def test_invalid_image(self):
        r=requests.post(self.url+'/image-ocr',json={'image_base64':'%%%'},headers=self.headers)
        self.assertEqual(r.status_code,400)
    def test_real_png_and_jpeg_ocr(self):
        for name in ('ocr_fixture.png','ocr_fixture.jpg'):
            data={'image_base64':base64.b64encode((root/name).read_bytes()).decode()}
            r=requests.post(self.url+'/image-ocr',json=data,headers=self.headers,timeout=35)
            self.assertEqual(r.status_code,200,r.text)
            text=''.join(r.json()['lines']).replace(' ','').replace('-','')
            self.assertIn('4111222233334444',text)
    def test_image_evidence_is_metadata_only(self):
        body=dict(target='chatgpt.com',file_name='capture.png',file_size=1234,match_status='matched',trace_id=str(uuid4()),
            image_guard={'outcome':'blocked_match','channel':'paste','cache_hit':False},
            match=dict(source_trace_id=str(uuid4()),source_kind='DB_SCREEN_VIEW',source_domain='desktop-oli.tail2bbbea.ts.net',
                source_path='/db',source_time=datetime.now(timezone.utc).isoformat(),method='windows_ocr_db_cells',age_seconds=1,candidate_count=1),
            image_base64='must-not-be-logged',ocr_text='must-not-be-logged')
        r=requests.post(self.url+'/image-event',json=body,headers=self.headers)
        self.assertEqual(r.status_code,200,r.text)
        event=self.events[-1]
        self.assertEqual(event['image_guard']['outcome'],'blocked_match')
        self.assertEqual(event['bytes_sent'],0)
        self.assertNotIn('must-not-be-logged',json.dumps(event))
        body['image_guard']['outcome']='no_match'
        self.assertEqual(requests.post(self.url+'/image-event',json=body,headers=self.headers).status_code,400)
    def test_ocr_failure_is_not_success(self):
        original=agent.recognize_image
        try:
            agent.recognize_image=lambda data:{'status':'error','error':'OCR_TIMEOUT'}
            r=requests.post(self.url+'/image-ocr',json={},headers=self.headers)
            self.assertEqual(r.status_code,422)
        finally:agent.recognize_image=original
    def test_formats_and_size(self):
        with self.assertRaises(ValueError):recognize_image({'image_base64':base64.b64encode(b'GIF89a').decode()})
        with self.assertRaises(ValueError):recognize_image({'image_base64':'A'*12000000})

if __name__=='__main__':unittest.main(verbosity=2)
