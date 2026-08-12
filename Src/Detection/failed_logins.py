"""Detection engine for failed login attempts in normalized log data."""

from collections import defaultdict
from typing import Any, Dict, List


class FailedLoginDetector:
    """Detect failed login attempts from parsed log entries."""

    def detect(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Inspect a list of parsed log dictionaries and return failed-login alerts.

        Supported indicators:
        - event_type contains 'failed login'
        - event_type contains 'failed logon'
        - status equals 'failed'
        - status equals 'invalid_user'
        """
        alerts: List[Dict[str, Any]] = []

        for log in logs or []:
            if not isinstance(log, dict):
                continue

            event_type = str(log.get('event_type', '')).lower()
            status = str(log.get('status', '')).lower()

            is_failed_login = (
                'failed login' in event_type or
                'failed logon' in event_type or
                'failed password' in event_type or
                status == 'failed' or
                status == 'invalid_user'
            )

            if not is_failed_login:
                continue

            alert = {
                'alert_type': 'Failed login',
                'timestamp': log.get('timestamp', ''),
                'source': log.get('source', ''),
                'ip': log.get('ip', ''),
                'username': log.get('username', ''),
                'event_id': log.get('event_id'),
                'message': log.get('message', ''),
                'severity': 'medium',
            }
            alerts.append(alert)

        return alerts

    def detect_summary(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Group failed login alerts by IP and count occurrences."""
        alert_list = self.detect(logs)
        counts = defaultdict(int)

        for alert in alert_list:
            ip = alert.get('ip', '')
            if ip:
                counts[ip] += 1

        return {
            'total_failed_logins': len(alert_list),
            'failed_logins_by_ip': dict(sorted(counts.items())),
        }


if __name__ == '__main__':
    detector = FailedLoginDetector()
    sample_logs = [
        {
            'timestamp': '2026-08-12 15:03:00',
            'source': 'ssh',
            'event_type': 'Failed login',
            'ip': '192.168.1.50',
            'status': 'failed',
            'message': 'Failed password for admin from 192.168.1.50 port 45234 ssh2',
            'username': 'admin',
            'event_id': 1,
        },
        {
            'timestamp': '2026-08-12 15:05:00',
            'source': 'windows',
            'event_type': 'Failed logon',
            'ip': '10.0.0.12',
            'status': 'failed',
            'message': 'EventID: 4625 Failed account logon',
            'username': 'svcuser',
            'event_id': 2,
        },
        {
            'timestamp': '2026-08-12 15:10:00',
            'source': 'ssh',
            'event_type': 'Successful login',
            'ip': '192.168.1.12',
            'status': 'success',
            'message': 'Accepted publickey for admin from 192.168.1.12 port 4422 ssh2',
            'username': 'admin',
            'event_id': 3,
        },
    ]

    print(detector.detect(sample_logs))
    print(detector.detect_summary(sample_logs))
