"""Portable identity and grant-isolation tests; no Windows or production DB needed."""
import importlib.util
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('agent_identity_under_test',
    Path(__file__).resolve().parents[1] / 'guard/agent/site_access.py')
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


class DeviceIdentityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_same_cloned_metadata_produces_distinct_ids(self):
        with patch.dict(os.environ, {'COMPUTERNAME': 'SAME-PC'}):
            a = identity.device_id(self.root / 'pc-a/device_uuid')
            b = identity.device_id(self.root / 'pc-b/device_uuid')
        self.assertNotEqual(a, b)
        self.assertRegex(a, r'^[a-f0-9]{64}$')
        self.assertRegex(b, r'^[a-f0-9]{64}$')

    def test_restart_and_app_relocation_keep_id(self):
        path = self.root / 'state/device_uuid'
        a = identity.device_id(path)
        with patch.dict(os.environ, {'COMPUTERNAME': 'RENAMED', 'GIGANG_APP_ROOT': '/other/app'}):
            self.assertEqual(a, identity.device_id(path))

    def test_simultaneous_first_launch_uses_one_complete_uuid(self):
        path = self.root / 'state/device_uuid'
        with ThreadPoolExecutor(max_workers=12) as pool:
            ids = list(pool.map(lambda _: identity.device_id(path), range(36)))
        self.assertEqual(len(set(ids)), 1)
        self.assertEqual(list(path.parent.iterdir()), [path])

    def test_corrupt_file_stops_instead_of_changing_identity(self):
        path = self.root / 'device_uuid'
        path.write_text('broken')
        with self.assertRaisesRegex(RuntimeError, '기기 ID'):
            identity.device_id(path)
        self.assertEqual(path.read_text(), 'broken')

    def test_unwritable_storage_does_not_fallback_to_hostname(self):
        with patch.object(identity.os, 'link', side_effect=PermissionError('denied')):
            with self.assertRaises(RuntimeError):
                identity.device_id(self.root / 'state/device_uuid')

    def test_windows_storage_is_machine_local_and_outside_app(self):
        with patch.object(identity.sys, 'platform', 'win32'), patch.dict(os.environ,
                {'PROGRAMDATA': str(self.root), 'GIGANG_DEVICE_ID_FILE': ''}):
            self.assertEqual(identity.identity_file(), self.root / 'GIGANG/device_uuid')

    def test_grant_for_pc_a_is_not_received_by_pc_b(self):
        with patch.object(identity, 'identity_file', return_value=self.root / 'a/device_uuid'):
            a = identity.SiteAccess('https://test.invalid')
        with patch.object(identity, 'identity_file', return_value=self.root / 'b/device_uuid'):
            b = identity.SiteAccess('https://test.invalid')
        grant = {'domain': 'example.com', 'grant_id': 'only-a',
                 'expires_at': (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()}
        requested = []
        def get(url, params, timeout):
            requested.append(params['device_id'])
            response = Mock()
            response.json.return_value = {'grants': [grant] if params['device_id'] == a.device else []}
            return response
        with patch.object(identity.requests, 'get', side_effect=get):
            self.assertEqual(a.permission('example.com', force=True)['grant_id'], 'only-a')
            self.assertIsNone(b.permission('example.com', force=True))
        self.assertEqual(requested, [a.device, b.device])


if __name__ == '__main__':
    unittest.main()
