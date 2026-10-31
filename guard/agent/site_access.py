"""Read central device grants. An unavailable/stale policy never grants access."""
import hashlib
import os
import sys
import tempfile
import uuid
from pathlib import Path
import threading
import time
from datetime import datetime
import requests


def identity_file():
    """Use machine-local state outside the application/update directory."""
    override = os.environ.get('GIGANG_DEVICE_ID_FILE')
    if override:
        return Path(override).expanduser()
    if sys.platform == 'win32':
        root = Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData'))
    elif sys.platform == 'darwin':
        root = Path.home() / 'Library' / 'Application Support'
    else:
        root = Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local' / 'state')))
    return root / 'GIGANG' / 'device_uuid'


def device_id(path=None):
    path = Path(path) if path is not None else identity_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            # Publish a complete file atomically, without replacing a competing
            # first launch's UUID. Never derive identity from cloned OS metadata.
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                             dir=path.parent, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(str(uuid.uuid4()))
                stream.flush()
                os.fsync(stream.fileno())
            try:
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    pass
            finally:
                temporary.unlink(missing_ok=True)
        value = str(uuid.UUID(path.read_text(encoding='utf-8').strip()))
    except (OSError, ValueError) as error:
        raise RuntimeError(
            'GIGANG 기기 ID 파일을 읽거나 저장할 수 없습니다: ' + str(path) +
            '. 권한과 파일 내용을 확인하세요. 기존 ID를 임의로 삭제하지 마세요.'
        ) from error
    # Preserve the server's existing 64-character lowercase hex contract.
    return hashlib.sha256(('gigang-device-uuid-v1:' + value).encode()).hexdigest()


def canonical_host(domain):
    host = domain.lower().rstrip('.')
    return host[4:] if host.startswith('www.') else host


class SiteAccess:
    def __init__(self, base):
        self.base = base
        self.device = device_id()
        self.grants = []
        self.checked = 0
        self.lock = threading.Lock()

    def refresh(self, force=False):
        requested_at = time.monotonic()
        with self.lock:
            # Reuse only a response completed after this request started when forced.
            # Ordinary background/hosts reads have at most a one-second cache.
            if (force and self.checked >= requested_at) or (not force and time.monotonic() - self.checked < 1):
                return
            try:
                response = requests.get(self.base + '/site-access/device', params={'device_id':self.device}, timeout=3)
                response.raise_for_status()
                rows = response.json()['grants']
                if not isinstance(rows, list):
                    raise ValueError('Invalid grants')
                self.grants = rows
            except (requests.RequestException, ValueError, KeyError):
                self.grants = []
            self.checked = time.monotonic()

    def permission(self, domain, force=False):
        self.refresh(force=force)
        now = time.time()
        for grant in self.grants:
            try:
                if canonical_host(grant['domain']) == canonical_host(domain) and datetime.fromisoformat(grant['expires_at']).timestamp() > now:
                    return {'status':'approved', 'grant_id':grant['grant_id'], 'expires_at':grant['expires_at']}
            except (KeyError, TypeError, ValueError):
                continue
        return None

    def effective_domains(self, domains):
        # A parent-domain hosts rule cannot be removed by a narrower child grant.
        self.refresh()
        return [domain for domain in domains if not self.permission(domain)]
