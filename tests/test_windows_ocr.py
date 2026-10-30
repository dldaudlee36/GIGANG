import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'guard'/'agent'))
from image_ocr import recognize_image
from rules import scan_text
from gigang.engine import policy as P

@unittest.skipUnless(sys.platform=='win32','Windows OCR test')
class WindowsOcrTests(unittest.TestCase):
    def test_real_capture_to_source_and_outbound_scores(self):
        from PIL import Image,ImageDraw,ImageFont
        font_path=Path(os.environ.get('SystemRoot','C:/Windows'))/'Fonts/arial.ttf'
        if not font_path.exists():self.skipTest('Arial font unavailable')
        with tempfile.TemporaryDirectory() as folder:
            im=Image.new('RGB',(1400,280),'white');d=ImageDraw.Draw(im)
            font=ImageFont.truetype(str(font_path),64)
            d.text((30,30),'010-1234-5678',font=font,fill='black')
            d.text((30,150),'900101-1234567',font=font,fill='black')
            path=Path(folder)/'fixture.png';im.save(path)
            result=recognize_image({'image_base64':base64.b64encode(path.read_bytes()).decode()})
        if result.get('error')=='OCR_LANGUAGE_UNAVAILABLE':self.skipTest('Windows OCR language unavailable')
        self.assertEqual(result.get('status'),'ok',result)
        hits=scan_text('\n'.join(result['lines']))
        self.assertEqual(hits['phone'],1,result)
        self.assertEqual(hits['rrn'],1,result)
        policy=P.load_policy()
        source=P.judge_portal('DB_IMAGE_CAPTURE','audit',{'inspectable':True,'pattern_hits':hits},policy)
        self.assertEqual((source.level,source.score),('WATCH',72))
        outbound=P.score_outbound(counts=P.effective_counts(hits,policy),relation='content',external=True,
                                   watched=True,policy=policy)
        self.assertEqual((outbound.level,outbound.score),('HIGH',82))

if __name__=='__main__':unittest.main()
