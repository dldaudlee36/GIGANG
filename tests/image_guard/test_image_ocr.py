import base64
import importlib.util
import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

root=Path(__file__).parent
spec=importlib.util.spec_from_file_location('image_ocr',root.parent.parent/'guard/agent/image_ocr.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
font=ImageFont.truetype('C:/Windows/Fonts/malgun.ttf',36)
image=Image.new('RGB',(1400,270),'white');draw=ImageDraw.Draw(image)
draw.text((30,30),'테스트 고객정보 (가상 데이터)',font=font,fill='black')
draw.text((30,100),'김테스트   900101-1234567   4111-2222-3333-4444',font=font,fill='black')
draw.text((30,170),'테스트영업부   서울특별시   test@example.invalid',font=font,fill='black')
path=root/'ocr_fixture.png';image.save(path)
result=module.recognize_image({'image_base64':base64.b64encode(path.read_bytes()).decode()})
(root/'ocr_fixture_result.json').write_text(json.dumps(result,ensure_ascii=False),encoding='utf-8')
print(json.dumps(result,ensure_ascii=False))
assert result['status']=='ok',result
assert '4111' in ''.join(result['lines'])
print('Windows Korean OCR fixture: PASS')
