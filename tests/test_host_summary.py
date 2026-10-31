"""Device summaries must not merge hosts sharing a cloned device ID."""
import unittest
from gigang.ui.host_summary import summarize_hosts


def event(device='', ip='unknown', pc='SAME-PC'):
    return dict(deviceId=device, pcName=pc, ip=ip, time='2026-10-31 12:00:00', user='User')


class HostSummaryTest(unittest.TestCase):
    def test_same_name_and_cloned_id_with_three_ips(self):
        rows = [event('cloned', '10.0.0.' + str(i)) for i in range(1, 4)]
        groups = summarize_hosts(rows)
        self.assertEqual(len(groups), 3)
        self.assertTrue(all(g['identityConflict'] for g in groups))

    def test_distinct_ids_with_missing_ip(self):
        self.assertEqual(len(summarize_hosts([event('a'), event('b'), event('c')])), 3)

    def test_exact_identity_aggregates(self):
        groups = summarize_hosts([event('a', '10.0.0.1'), event('a', '10.0.0.1')])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]['count'], 2)

    def test_missing_identity_is_not_presented_as_a_known_device(self):
        groups = summarize_hosts([event(), event()])
        self.assertEqual(groups[0]['identityMode'], 'unidentified')
        self.assertEqual(groups[0]['count'], 2)


if __name__ == '__main__':
    unittest.main()
