# Reproducible checks

Run from this directory on Windows with Korean OCR enabled.

```
python test_image_ocr.py
node test_image_match.cjs
node test_image_interception.cjs
python test_image_api.py
python test_image_risk.py
```

Dependencies: Python requests, Pillow (fixture generation), project dependencies for the risk test, and Node.js. The fixture contains synthetic customer data. API tests bind an ephemeral loopback port and stub external event delivery; they do not modify hosts or contact Railway. Event interception tests use mocked DOM events and do not prove Chrome or third-party site compatibility. Real-browser testing remains outstanding because the test Chromium process could not be spawned in this environment.
