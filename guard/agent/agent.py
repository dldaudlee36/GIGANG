"""GIGANG Agent v3.9 (Integrated):
- Event collection (DNS, paste, file selection, drag-and-drop, confidential-DB copy, screenshot, download)
- Railway central policy & Windows hosts blocking & SiteAccess temporary unblock
- Confidential DB content rules scanning (rules.py) & file inspection (files.py)
- Clipboard image OCR guard (image_ocr.py, clipboard_watch.py)
"""
import ctypes
import ctypes.wintypes
import getpass
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
import requests

from portal_inspection import inspect_content, metadata as inspection_metadata
from rules import scan_text
from files import inspect_file
from link_metadata import link_metadata
from image_ocr import recognize_image
import clipboard_watch
from site_access import SiteAccess

VERSION = '3.9.0'
PROJECT_ROOT = Path(os.environ.get('GIGANG_APP_ROOT', str(Path(__file__).resolve().parents[2])))

try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / '.env')
except Exception:
    pass

SERVER_URL = os.getenv('RAILWAY_URL', 'https://bountiful-nature-production-22ec.up.railway.app/events')
SERVER_BASE = SERVER_URL.rsplit('/', 1)[0] if SERVER_URL.rstrip('/').endswith('/events') else SERVER_URL.rstrip('/')
POLICY_URL = os.getenv('RAILWAY_POLICY_URL', SERVER_BASE + '/policy')
SITE_ACCESS = SiteAccess(SERVER_BASE)
SERVER_DOMAIN = urlsplit(SERVER_URL).hostname
LOCAL_EXTENSION_PORT = int(os.getenv('GIGANG_EXTENSION_PORT', '8765'))
POLICY_SYNC_SECONDS = max(1, int(os.getenv('GIGANG_POLICY_SYNC_SECONDS', '1')))
USER_NAME = getpass.getuser()
PC_NAME = socket.gethostname()
BLOCKLIST_FILE = PROJECT_ROOT / 'runtime' / 'blocked_domains.json'
_policy_status = {'ok': None, 'last_success': None, 'error': None}
_hosts_status = {'ok': None, 'last_apply': None, 'error': None, 'blocked_count': 0}
HOSTS_BEGIN = '# BEGIN GIGANG MANAGED BLOCK'
HOSTS_END = '# END GIGANG MANAGED BLOCK'
HOSTS_PATH = Path(os.environ.get('WINDIR', r'C:\Windows')) / 'System32' / 'drivers' / 'etc' / 'hosts'

CONFIDENTIAL_URLS = [u.strip() for u in os.getenv('GIGANG_CONFIDENTIAL_URLS',
                                                  'desktop-oli.tail2bbbea.ts.net').split(',') if u.strip()]
CLIPBOARD_POLL_SECONDS = 0.3
CF_UNICODETEXT = 13
CF_DIB = 8
CAPTURE_WAIT_SECONDS = 60
BROWSER_PROCESSES = {'chrome.exe', 'msedge.exe', 'whale.exe'}

DOWNLOADED = {}
MAX_DOWNLOADED = 500
ACTIVE_TAB = {'source': None}


def normalize_domain(value):
    if not isinstance(value, str):
        return ''
    value = value.strip().lower()
    value = re.sub(r'^https?://', '', value)
    value = value.split('/', 1)[0].split(':', 1)[0].strip('.')
    if not value or len(value) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]', value):
        return ''
    return value


def load_blocklist():
    try:
        payload = json.loads(BLOCKLIST_FILE.read_text(encoding='utf-8'))
        raw = payload.get('blocked_domains', []) if isinstance(payload, dict) else []
        source_updated_at = payload.get('updated_at') if isinstance(payload, dict) else None
    except (FileNotFoundError, OSError, ValueError, TypeError):
        raw, source_updated_at = [], None
    domains = sorted({normalize_domain(item) for item in raw if normalize_domain(item)})
    return {
        'blocked_domains': domains,
        'updated_at': source_updated_at,
        'central_sync': dict(_policy_status),
    }


def save_blocklist(domains, updated_at=None):
    clean = sorted({normalize_domain(item) for item in domains if normalize_domain(item)})
    BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        'blocked_domains': clean,
        'updated_at': updated_at or datetime.now(timezone.utc).isoformat(),
        'source': 'railway-central-policy',
    }
    temp = BLOCKLIST_FILE.with_suffix('.tmp')
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.replace(BLOCKLIST_FILE)
    return clean


def _strip_managed_hosts_block(lines):
    out = []
    inside = False
    for line in lines:
        marker = line.strip()
        if marker == HOSTS_BEGIN:
            inside = True
            continue
        if inside and marker == HOSTS_END:
            inside = False
            continue
        if not inside:
            out.append(line)
    return out


def _hosts_domains(domains):
    names = set()
    for d in domains:
        norm = normalize_domain(d)
        if norm:
            names.add(norm)
            if not norm.startswith('www.'):
                names.add('www.' + norm)
    return sorted(names)


def apply_windows_blocklist(domains):
    clean = _hosts_domains(domains)
    try:
        content = HOSTS_PATH.read_text(encoding='utf-8', errors='ignore') if HOSTS_PATH.exists() else ''
        lines = _strip_managed_hosts_block(content.splitlines())
        while lines and not lines[-1].strip():
            lines.pop()
        if clean:
            lines.append('')
            lines.append(HOSTS_BEGIN)
            for d in clean:
                lines.append(f'0.0.0.0 {d}')
            lines.append(HOSTS_END)
            lines.append('')
        new_text = '\n'.join(lines) + ('\n' if lines else '')
        if new_text != content:
            temp = HOSTS_PATH.with_suffix('.gigang.tmp')
            temp.write_text(new_text, encoding='utf-8')
            temp.replace(HOSTS_PATH)
        _hosts_status.update(ok=True, last_apply=datetime.now(timezone.utc).isoformat(), error=None, blocked_count=len(clean))
        return True
    except OSError as error:
        _hosts_status.update(ok=False, error=type(error).__name__)
        return False


def apply_saved_policy():
    data = load_blocklist()
    return apply_windows_blocklist(SITE_ACCESS.effective_domains(data['blocked_domains']))


def sync_central_policy():
    try:
        response = requests.get(POLICY_URL, timeout=5, headers={'Cache-Control': 'no-cache'})
        response.raise_for_status()
        payload = response.json()
        raw = payload.get('blocked_domains', []) if isinstance(payload, dict) else None
        if not isinstance(raw, list):
            raise ValueError('invalid policy payload')
        clean = save_blocklist(raw, payload.get('updated_at'))
        hosts_ok = apply_windows_blocklist(SITE_ACCESS.effective_domains(clean))
        _policy_status.update(ok=True, last_success=datetime.now(timezone.utc).isoformat(), error=None, detail=None)
        return hosts_ok
    except (requests.RequestException, ValueError, TypeError) as error:
        _policy_status.update(ok=False, error=type(error).__name__, detail=str(error)[:800])
        apply_saved_policy()
        return False


def policy_sync_loop():
    while True:
        sync_central_policy()
        time.sleep(POLICY_SYNC_SECONDS)


def get_local_ip():
    try:
        value = socket.gethostbyname(socket.gethostname())
        if not ipaddress.ip_address(value).is_loopback:
            return value
    except (OSError, ValueError):
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((SERVER_DOMAIN, 443))
            return probe.getsockname()[0]
    except OSError:
        return 'unknown'


def base_event(kind, target):
    return {'user': USER_NAME, 'pc_name': PC_NAME, 'local_ip': get_local_ip(),
            'event_type': kind, 'target': target, 'agent_version': VERSION,
            'device_id': SITE_ACCESS.device}


def add_client_time(result, data):
    stamp = data.get('timestamp')
    if stamp is not None:
        if not isinstance(stamp, str) or len(stamp) > 64:
            raise ValueError('Valid timestamp required')
        parsed = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('Timestamp must include timezone')
        result['client_event_time'] = parsed.astimezone(timezone.utc).isoformat()


def confidential_source(address):
    if not address or not isinstance(address, str):
        return None
    try:
        url = urlsplit(address if '://' in address else '//' + address)
        host, path = (url.hostname or '').lower(), url.path.rstrip('/')
    except ValueError:
        return None
    for pattern in CONFIDENTIAL_URLS:
        try:
            p = urlsplit(pattern if '://' in pattern else '//' + pattern)
            p_host, p_path = (p.hostname or '').lower(), p.path.rstrip('/')
        except ValueError:
            continue
        if host == p_host and (not p_path or path == p_path or path.startswith(p_path + '/')):
            return pattern
    return None


def extension_event(path, data):
    if not isinstance(data, dict):
        raise ValueError('JSON object required')
    target = data.get('target')
    if not isinstance(target, str) or not target.strip() or len(target) > 253:
        raise ValueError('Valid site hostname required')
    kind = 'COPY_ATTEMPT' if path == '/copy-event' else 'PASTE_ATTEMPT' if path == '/paste-event' else 'FILE_UPLOAD_ATTEMPT'
    result = base_event(kind, target)
    result['source'] = 'chrome-extension'
    if kind == 'COPY_ATTEMPT':
        if target != 'desktop-oli.tail2bbbea.ts.net' or data.get('source_path') != '/db' or data.get('detection_scope') != 'customer_table':
            raise ValueError('Invalid portal copy')
        result.update(source_path='/db', detection_scope='customer_table')
    elif kind == 'PASTE_ATTEMPT':
        length = data.get('text_length')
        if type(length) is not int or not 0 <= length <= 100_000_000:
            raise ValueError('text_length must be a non-negative integer')
        result['text_length'] = length
        if 'image_count' in data:
            count, total = data.get('image_count'), data.get('image_bytes')
            if type(count) is not int or not 0 < count <= 1000 or type(total) is not int or total < 0:
                raise ValueError('Valid image metadata required')
            result.update(image_count=count, image_bytes=total)
        if length == 0 and 'image_count' not in result:
            raise ValueError('Text or image required')
    else:
        name, size = data.get('file_name'), data.get('file_size')
        if not isinstance(name, str) or len(name) > 1024:
            raise ValueError('Valid file name required')
        if type(size) is not int or size < 0:
            raise ValueError('Valid file size required')
        result.update(file_name=name, file_size=size)
        if 'method' in data:
            if data['method'] != 'drop':
                raise ValueError('Valid upload method required')
            result['method'] = 'drop'
        downloaded = DOWNLOADED.get((name, size))
        if downloaded:
            result['confidential_source'] = downloaded

    add_client_time(result, data)
    result.update(link_metadata(data, kind, target))
    result.update(inspection_metadata(data))
    attach_authorization(result, data)
    return result


def attach_authorization(event, data):
    requested = data.get('authorization')
    if isinstance(requested, dict):
        grant = SITE_ACCESS.permission(event['target'])
        if grant and requested.get('grant_id') == grant['grant_id']:
            event['authorization'] = grant


def download_event(data):
    if not isinstance(data, dict):
        raise ValueError('JSON object required')
    if data.get('event_type') in ('DOWNLOAD_STARTED', 'DOWNLOAD_COMPLETED', 'DOWNLOAD_INTERRUPTED'):
        if data.get('target') != 'desktop-oli.tail2bbbea.ts.net' or data.get('source_path') != '/db/download':
            raise ValueError('Invalid portal download')
        result = base_event(data['event_type'], data['target'])
        result.update(source='chrome-extension', source_path='/db/download',
                      download_id=data.get('download_id'), download_state=data.get('download_state'),
                      file_name=data.get('file_name'), file_size=data.get('file_size'))
        result.update(inspection_metadata(data))
        result.update(link_metadata(data, data['event_type'], data['target']))
        add_client_time(result, data)
        return result
    urls = [data.get(key) for key in ('url', 'final_url', 'referrer')]
    if any(url is not None and (not isinstance(url, str) or len(url) > 4096) for url in urls):
        raise ValueError('Valid download URL required')
    path = data.get('file_path')
    if not isinstance(path, str) or not path or len(path) > 1024:
        raise ValueError('Valid file path required')
    source = next((found for found in map(confidential_source, urls) if found), None)
    if not source:
        return None
    if not os.path.isfile(path):
        raise ValueError('Downloaded file not found')
    name, size = os.path.basename(path), os.path.getsize(path)
    result = base_event('DB_DOWNLOAD', source)
    result.update(source='windows-agent', file_name=name, file_size=size, **inspect_file(path))
    add_client_time(result, data)
    DOWNLOADED.pop((name, size), None)
    DOWNLOADED[(name, size)] = source
    while len(DOWNLOADED) > MAX_DOWNLOADED:
        DOWNLOADED.pop(next(iter(DOWNLOADED)))
    return result


def send_to_railway(event):
    try:
        response = requests.post(SERVER_URL, json=event, timeout=8)
        response.raise_for_status()
        print(f"[서버 전송 성공] {event['event_type']} {event['target']}", flush=True)
        return True
    except requests.RequestException as error:
        print(f"[서버 전송 실패] {type(error).__name__} {event['event_type']}", flush=True)
        return False


class ExtensionEventHandler(BaseHTTPRequestHandler):
    def respond(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Origin')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.respond(200, {})

    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path == '/health':
            policy = load_blocklist()
            self.respond(200, {
                'service': 'GIGANGAgent', 'version': VERSION,
                'blocked_count': len(policy['blocked_domains']),
                'central_policy_ok': _policy_status['ok'],
                'central_policy_last_success': _policy_status['last_success'],
                'central_policy_error': _policy_status.get('detail'),
                'windows_blocking_ok': _hosts_status['ok'],
                'windows_blocked_hostnames': _hosts_status['blocked_count'],
                'device_id': SITE_ACCESS.device,
                'clipboard_watch': dict(clipboard_watch.status),
                'active_tab': ACTIVE_TAB.get('source')
            })
        elif path == '/site-permission':
            domain = normalize_domain(parse_qs(urlsplit(self.path).query).get('domain', [''])[0])
            grant = SITE_ACCESS.permission(domain, force=True)
            self.respond(200, {'allowed': bool(grant), 'authorization': grant})
        elif path == '/blocklist':
            self.respond(200, load_blocklist())
        elif path == '/sync-policy':
            ok = sync_central_policy()
            self.respond(200 if ok else 502, load_blocklist())
        else:
            self.respond(404, {'error': 'Not found'})

    def do_POST(self):
        if self.path == '/inspect-content':
            if not re.fullmatch(r'chrome-extension://[a-p]{32}', self.headers.get('Origin', '')):
                self.respond(403, {'error': 'EXTENSION_ORIGIN_REQUIRED'})
                return
            try:
                count = int(self.headers.get('Content-Length', '0'))
                if not 0 < count <= 28002000: raise ValueError('Invalid inspection size')
                self.connection.settimeout(30)
                data = json.loads(self.rfile.read(count).decode('utf-8'))
                result = inspect_content(data)
                self.respond(200, {'status': 'ok', **result})
            except (ValueError, UnicodeError, OSError):
                self.respond(400, {'error': 'INSPECTION_FAILED'})
            return
        if self.path == '/active-tab':
            self.active_tab()
            return
        if self.path in ('/image-ocr', '/image-event', '/image-baseline', '/site-blocked'):
            origin = self.headers.get('Origin', '')
            if not re.fullmatch(r'chrome-extension://[a-p]{32}', origin):
                self.respond(403, {'error': 'EXTENSION_ORIGIN_REQUIRED'})
                return
            try:
                count = int(self.headers.get('Content-Length', '0'))
                limit = 11_200_000 if self.path == '/image-ocr' else 2_000_000 if self.path == '/image-baseline' else 16384
                if not 0 < count <= limit:
                    self.respond(413, {'error': 'IMAGE_REQUEST_TOO_LARGE'})
                    return
                self.connection.settimeout(15)
                data = json.loads(self.rfile.read(count).decode('utf-8'))
                if self.path == '/site-blocked':
                    target = normalize_domain(data.get('target'))
                    if not target: raise ValueError('Invalid target')
                    event = base_event('SITE_BLOCKED', target)
                    event['source'] = 'chrome-extension'
                    saved = send_to_railway(event)
                    self.respond(200 if saved else 502, {'status': 'saved' if saved else 'failed'})
                if self.path == '/image-baseline':
                    clipboard_watch.save_baseline(origin, data)
                    self.respond(200, {'status': 'ready'})
                    return
                if self.path == '/image-ocr':
                    result = recognize_image(data)
                    if result.get('status') == 'ok':
                        result['inspection'] = {'inspectable':True,'pattern_hits':scan_text('\n'.join(result['lines']))}
                    self.respond(200 if result.get('status') == 'ok' else 422, result)
                    return
                # /image-event
                event = extension_event('/upload-event', data)
                guard = data.get('image_guard')
                if not isinstance(guard, dict) or guard.get('outcome') not in ('blocked_match', 'held_error', 'no_match') or guard.get('channel') not in ('paste', 'file', 'drop'):
                    raise ValueError('Invalid image outcome')
                if (guard['outcome'] == 'blocked_match') != (event.get('match_status') == 'matched'):
                    raise ValueError('Inconsistent image result')
                error = guard.get('error')
                if error is not None and (not isinstance(error, str) or not re.fullmatch(r'[A-Z_]{1,64}', error)):
                    raise ValueError('Invalid image error')
                event['image_guard'] = {'outcome': guard['outcome'], 'channel': guard['channel'],
                                        'error': error, 'cache_hit': guard.get('cache_hit') is True}
                event['bytes_sent'] = 0
                attach_authorization(event, data)
                saved = send_to_railway(event)
                self.respond(200 if saved else 502, {'status': 'saved' if saved else 'failed', 'event_type': 'FILE_UPLOAD_ATTEMPT'})
            except Exception as e:
                self.respond(400, {'error': str(e)})
            return

        if self.path not in ('/copy-event', '/upload-event', '/paste-event', '/download-event'):
            self.respond(404, {'error': 'Not found'})
            return

        try:
            count = int(self.headers.get('Content-Length', '0'))
            if not 0 < count <= 16384:
                self.respond(413, {'error': 'Metadata payload too large or empty'})
                return
            data = json.loads(self.rfile.read(count).decode('utf-8'))
            if self.path == '/download-event':
                event = download_event(data)
            else:
                event = extension_event(self.path, data)
        except (ValueError, UnicodeError) as err:
            self.respond(400, {'error': f'Invalid event metadata: {err}'})
            return

        if event is None:
            self.respond(200, {'status': 'ignored'})
            return

        success = send_to_railway(event)
        if success:
            self.respond(200, {'status': 'saved', 'event_type': event['event_type']})
        else:
            self.respond(502, {'error': 'Railway delivery failed'})

    def active_tab(self):
        try:
            count = int(self.headers.get('Content-Length', '0'))
            if not 0 < count <= 4096:
                raise ValueError
            url = json.loads(self.rfile.read(count).decode('utf-8')).get('url')
            if not isinstance(url, str):
                raise ValueError
        except (ValueError, UnicodeError, AttributeError):
            self.respond(400, {'error': 'Invalid tab metadata'})
            return
        ACTIVE_TAB['source'] = confidential_source(url)
        self.respond(200, {'status': 'ok'})

    def log_message(self, *args):
        pass


if hasattr(ctypes, 'windll'):
    user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.GetClipboardData.argtypes = [ctypes.c_uint]
    user32.GetClipboardData.restype = ctypes.c_void_p
    user32.RegisterClipboardFormatW.argtypes = [ctypes.c_wchar_p]
    user32.RegisterClipboardFormatW.restype = ctypes.c_uint
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalSize.argtypes = [ctypes.c_void_p]
    kernel32.GlobalSize.restype = ctypes.c_size_t
    CF_HTML = user32.RegisterClipboardFormatW('HTML Format')
    user32.IsClipboardFormatAvailable.argtypes = [ctypes.c_uint]
    user32.GetForegroundWindow.restype = ctypes.c_void_p
    user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.wintypes.DWORD)]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.c_wchar_p,
                                                    ctypes.POINTER(ctypes.wintypes.DWORD)]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    LRESULT = ctypes.c_ssize_t
    HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM)
    user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC, ctypes.c_void_p, ctypes.wintypes.DWORD]
    user32.SetWindowsHookExW.restype = ctypes.c_void_p
    user32.CallNextHookEx.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM]
    user32.CallNextHookEx.restype = LRESULT
    user32.GetMessageW.argtypes = [ctypes.POINTER(ctypes.wintypes.MSG), ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint]


def is_browser_foreground():
    hwnd = user32.GetForegroundWindow()
    if not hwnd: return False
    pid = ctypes.wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    hproc = kernel32.OpenProcess(0x1000, False, pid.value)
    if not hproc: return False
    try:
        buf, size = ctypes.create_unicode_buffer(512), ctypes.wintypes.DWORD(512)
        if not kernel32.QueryFullProcessImageNameW(hproc, 0, buf, ctypes.byref(size)): return False
        return os.path.basename(buf.value).lower() in BROWSER_PROCESSES
    finally:
        kernel32.CloseHandle(hproc)


def clipboard_html_source():
    if not user32.IsClipboardFormatAvailable(CF_HTML): return None
    handle = user32.GetClipboardData(CF_HTML)
    if not handle: return None
    ptr = kernel32.GlobalLock(handle)
    if not ptr: return None
    try:
        raw = ctypes.string_at(ptr, min(kernel32.GlobalSize(handle), 8192)).decode('utf-8', errors='ignore')
        m = re.search(r'SourceURL:(.+)', raw)
        return m.group(1).strip() if m else None
    finally:
        kernel32.GlobalUnlock(handle)


def clipboard_text():
    if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT): return ''
    handle = user32.GetClipboardData(CF_UNICODETEXT)
    if not handle: return ''
    ptr = kernel32.GlobalLock(handle)
    if not ptr: return ''
    try:
        return ctypes.wstring_at(ptr)
    finally:
        kernel32.GlobalUnlock(handle)


def dib_dimensions():
    if not user32.IsClipboardFormatAvailable(CF_DIB): return None, None
    handle = user32.GetClipboardData(CF_DIB)
    if not handle: return None, None
    ptr = kernel32.GlobalLock(handle)
    if not ptr: return None, None
    try:
        header = ctypes.string_at(ptr, 12)
        if len(header) < 12: return None, None
        size, w, h = struct.unpack_from('<Iii', header)
        if size >= 40: return abs(w), abs(h)
        w, h = struct.unpack_from('<Hh', header, 4)
        return abs(w), abs(h)
    finally:
        kernel32.GlobalUnlock(handle)


KEY_EVENT = threading.Event()
LAST_KEY = {'name': None, 'time': 0}


def hook_proc(code, wparam, lparam):
    WM_KEYDOWN, WM_SYSKEYDOWN = 0x0100, 0x0104
    VK_SNAPSHOT = 0x2C
    if code >= 0 and wparam in (WM_KEYDOWN, WM_SYSKEYDOWN):
        vk = ctypes.cast(lparam, ctypes.POINTER(ctypes.wintypes.DWORD)).contents.value
        pressed = lambda k: bool(user32.GetAsyncKeyState(k) & 0x8000)
        now = time.monotonic()
        name = None
        if vk == ord('S') and pressed(0x5B) and pressed(0x10):
            name = 'Win+Shift+S'
        elif vk == VK_SNAPSHOT:
            name = 'Alt+PrtSc' if pressed(0x12) else 'PrtSc'
        if name:
            LAST_KEY.update(name=name, time=now)
            KEY_EVENT.set()
    return user32.CallNextHookEx(None, code, wparam, lparam)


def run_keyboard_hook():
    cb = HOOKPROC(hook_proc)
    WH_KEYBOARD_LL = 13
    hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, cb, kernel32.GetModuleHandleW(None), 0)
    if not hook:
        print("[Agent 경고] 캡처 단축키 후크 설치 실패", flush=True)
        return
    msg = ctypes.wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        pass


def clipboard_poll_loop():
    last_seq = 0
    while True:
        try:
            seq = user32.GetClipboardSequenceNumber()
            if seq != last_seq:
                last_seq = seq
                user32.OpenClipboard(None)
                try:
                    is_image = bool(user32.IsClipboardFormatAvailable(CF_DIB))
                    is_text = bool(user32.IsClipboardFormatAvailable(CF_UNICODETEXT))
                    src_url = clipboard_html_source()
                    text = clipboard_text() if is_text else ''
                    w, h = dib_dimensions() if is_image else (None, None)
                finally:
                    user32.CloseClipboard()

                # 1. 캡처 판정
                if is_image and LAST_KEY['name'] and (time.monotonic() - LAST_KEY['time'] <= CAPTURE_WAIT_SECONDS):
                    src = ACTIVE_TAB.get('source') if is_browser_foreground() else None
                    if src:
                        ev = base_event('SCREEN_CAPTURE', src)
                        ev.update(source='windows-agent', shortcut=LAST_KEY['name'],
                                  image_width=w, image_height=h)
                        send_to_railway(ev)
                        LAST_KEY.update(name=None, time=0)

                # 2. 기밀 DB 텍스트 복사 판정
                matched_source = confidential_source(src_url)
                if matched_source and text:
                    hits = scan_text(text)
                    ev = base_event('CLIPBOARD_COPY', matched_source)
                    ev.update(source='windows-agent', text_length=len(text), pattern_hits=hits)
                    send_to_railway(ev)
        except Exception:
            pass
        time.sleep(CLIPBOARD_POLL_SECONDS)


def start_server():
    server = ThreadingHTTPServer(('127.0.0.1', LOCAL_EXTENSION_PORT), ExtensionEventHandler)
    print(f"[Agent v{VERSION}] Local Extension Listener started on 127.0.0.1:{LOCAL_EXTENSION_PORT}", flush=True)
    server.serve_forever()


def main():
    print(f"=== GIGANG Agent v{VERSION} ===", flush=True)
    print(f"User: {USER_NAME} | Host: {PC_NAME} | Local IP: {get_local_ip()}", flush=True)

    # 1. 중앙 정책 동기화 & hosts 차단 적용
    sync_central_policy()
    t_sync = threading.Thread(target=policy_sync_loop, daemon=True, name='PolicySync')
    t_sync.start()

    # 2. 이미지 가드 클립보드 감시 시작
    clipboard_watch.start(recognize_image, base_event, send_to_railway)

    # 3. 키보드 단축키 후크 (캡처 감지)
    if hasattr(ctypes, 'windll'):
        t_hook = threading.Thread(target=run_keyboard_hook, daemon=True, name='KeyboardHook')
        t_hook.start()
        t_poll = threading.Thread(target=clipboard_poll_loop, daemon=True, name='ClipboardPoll')
        t_poll.start()

    # 4. 로컬 HTTP 서버 실행
    start_server()


if __name__ == '__main__':
    main()
