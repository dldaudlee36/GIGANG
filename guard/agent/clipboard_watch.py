"""Inspect new clipboard bitmaps locally; retain only expiring DB cell digests."""
from rules import scan_text
import base64
import ctypes
import hashlib
import io
import re
import threading
import time
import unicodedata
import uuid
from datetime import datetime, timezone

TTL = 1800
_lock = threading.Lock()
_baselines = {}
status = {'running': False, 'last_check': None, 'error': None}


def save_baseline(origin, data):
    seed, rows = data.get('seed'), data.get('rows')
    if not isinstance(seed, str) or not 1 <= len(seed) <= 128 or not isinstance(rows, list) or len(rows) > 500:
        raise ValueError('Invalid baseline')
    now = time.time() * 1000
    clean = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('tokens'), list) or len(row['tokens']) > 30:
            raise ValueError('Invalid row')
        if not isinstance(row.get('observed'), (int, float)) or not 0 <= now - row['observed'] < TTL * 1000:
            continue
        for token in row['tokens']:
            if (not re.fullmatch('[a-f0-9]{64}', str(token.get('hash', ''))) or
                    type(token.get('length')) is not int or not 3 <= token['length'] <= 32 or
                    type(token.get('strong')) is not bool):
                raise ValueError('Invalid token')
        clean.append({'tokens': row['tokens'], 'observed': row['observed']})
    with _lock:
        _baselines[origin] = (seed, clean)


def match_lines(lines, seed, rows, now=None):
    now = time.time() * 1000 if now is None else now
    rows = [r for r in rows if 0 <= now - r['observed'] < TTL * 1000]
    text = ''.join(c for c in unicodedata.normalize('NFKC', ' '.join(lines)).lower()
                   if unicodedata.category(c)[0] in ('L', 'N'))
    if not text or len(text) > 24000:
        return False
    lengths = {t['length'] for r in rows for t in r['tokens']}
    if sum(max(0, len(text) - n + 1) for n in lengths) > 250000:
        return False
    wanted = {t['hash'] for r in rows for t in r['tokens']}
    found = set()
    for n in lengths:
        for i in range(len(text) - n + 1):
            value = hashlib.sha256((seed + '\0image-cell\0' + text[i:i+n]).encode()).hexdigest()
            if value in wanted:
                found.add(value)
    return any(any(t['strong'] and t['hash'] in found for t in r['tokens']) or
               len({t['hash'] for t in r['tokens'] if t['hash'] in found}) >= 3 for r in rows)


def monitor(recognize, base_event, send):
    from PIL import Image, ImageGrab
    sequence = ctypes.windll.user32.GetClipboardSequenceNumber
    last = sequence()  # Do not inspect clipboard contents left before Agent startup.
    status.update(running=True, error=None)
    while True:
        time.sleep(0.8)
        current = sequence()
        if current == last:
            continue
        with _lock:
            now = time.time() * 1000
            baselines = [(seed, [r for r in rows if 0 <= now-r['observed'] < TTL*1000])
                         for seed, rows in _baselines.values()]
        if not any(rows for _, rows in baselines):
            last = current
            continue
        try:
            bitmap = ImageGrab.grabclipboard()
            if sequence() != current:
                continue
            if not isinstance(bitmap, Image.Image):
                last = current
                continue  # Never read file paths from the clipboard.
            last = current
            if bitmap.width * bitmap.height > 16000000:
                status['error'] = 'IMAGE_TOO_LARGE'
                continue
            buffer = io.BytesIO()
            bitmap.convert('RGB').save(buffer, format='PNG')
            if buffer.tell() > 8 * 1024 * 1024:
                status['error'] = 'IMAGE_TOO_LARGE'
                continue
            result = recognize({'image_base64': base64.b64encode(buffer.getvalue()).decode('ascii')})
            if result.get('error') == 'OCR_BUSY':
                last = None  # Retry the current image when upload inspection releases OCR.
                continue
            status.update(last_check=datetime.now(timezone.utc).isoformat(), error=result.get('error'))
            if result.get('status') != 'ok':
                continue
            if any(match_lines(result['lines'], seed, rows) for seed, rows in baselines):
                event = base_event('DB_IMAGE_CAPTURE', 'desktop-oli.tail2bbbea.ts.net')
                event.update(source='windows-agent', source_path='/db', detection_scope='db_image_content',
                             inspectable=True, pattern_hits=scan_text('\n'.join(result['lines'])),
                             capture_source='clipboard_image', trace_id=str(uuid.uuid4()),
                             client_event_time=datetime.now(timezone.utc).isoformat())
                send(event)
        except Exception as error:
            status['error'] = type(error).__name__


def start(recognize, base_event, send):
    def run():
        try:
            monitor(recognize, base_event, send)
        except Exception as error:
            status.update(running=False, error=type(error).__name__)
    threading.Thread(target=run, daemon=True, name='clipboard-image-watch').start()
