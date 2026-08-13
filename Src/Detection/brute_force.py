"""Detection engine for brute-force login activity."""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List


class BruteForceDetector:
    """Detect repeated failed login attempts from the same IP within a time window."""

    FAILURE_THRESHOLD = 5
    WINDOW_SECONDS = 300

    @staticmethod
    def _is_failed_login(log: Dict[str, Any]) -> bool:
        """Return True if the log entry represents a failed authentication event."""
        if not isinstance(log, dict):
            return False

        event_type = str(log.get('event_type', '')).lower()
        status = str(log.get('status', '')).lower()

        return (
            'failed login' in event_type or
            'failed logon' in event_type or
            'failed password' in event_type or
            status == 'failed' or
            status == 'invalid_user'
        )

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        """Parse various timestamp formats from normalized logs."""
        if value is None or value == '':
            return None

        if isinstance(value, datetime):
            return value

        value_str = str(value).strip()
        formats = (
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%b %d %H:%M:%S',
        )

        for fmt in formats:
            try:
                return datetime.strptime(value_str, fmt)
            except ValueError:
                continue

        try:
            return datetime.fromisoformat(value_str.replace('Z', '+00:00'))
        except ValueError:
            return None

    def detect(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Check for 5 failed logins from the same IP within 300 seconds.

        Returns a list of brute-force alerts. Each alert contains the IP,
        the triggering timestamp, and the rule criteria that were met.
        """
        window_by_ip: Dict[str, Deque[datetime]] = defaultdict(deque)
        last_alerted: Dict[str, datetime] = {}
        alerts: List[Dict[str, Any]] = []

        for log in logs or []:
            if not self._is_failed_login(log):
                continue

            ip = str(log.get('ip', '')).strip()
            if not ip:
                continue

            timestamp = self._parse_timestamp(log.get('timestamp'))
            if timestamp is None:
                continue

            attempts = window_by_ip[ip]
            attempts.append(timestamp)

            while attempts and (timestamp - attempts[0]).total_seconds() > self.WINDOW_SECONDS:
                attempts.popleft()

            if len(attempts) < self.FAILURE_THRESHOLD:
                continue

            previous_alert = last_alerted.get(ip)
            if previous_alert is not None and (timestamp - previous_alert).total_seconds() <= self.WINDOW_SECONDS:
                continue

            alerts.append({
                'alert_type': 'Brute force attack',
                'timestamp': log.get('timestamp', ''),
                'source': log.get('source', ''),
                'ip': ip,
                'username': log.get('username', ''),
                'event_id': log.get('event_id'),
                'message': (
                    f"{self.FAILURE_THRESHOLD} failed logins from {ip} within "
                    f"{self.WINDOW_SECONDS} seconds"
                ),
                'severity': 'high',
                'threshold': self.FAILURE_THRESHOLD,
                'window_seconds': self.WINDOW_SECONDS,
            })
            last_alerted[ip] = timestamp

        return alerts

    def detect_summary(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize brute-force alerts by offending IP."""
        alert_list = self.detect(logs)
        counts = defaultdict(int)

        for alert in alert_list:
            ip = alert.get('ip', '')
            if ip:
                counts[ip] += 1

        return {
            'total_brute_force_alerts': len(alert_list),
            'brute_force_by_ip': dict(sorted(counts.items())),
        }


if __name__ == '__main__':
    detector = BruteForceDetector()
    sample_logs = [
        {
            'timestamp': '2026-08-12 15:00:00',
            'source': 'ssh',
            'event_type': 'Failed login',
            'ip': '192.168.1.50',
            'status': 'failed',
            'message': 'Failed password for admin from 192.168.1.50 port 45234 ssh2',
            'username': 'admin',
            'event_id': 1,
        },
        {
            'timestamp': '2026-08-12 15:00:30',
            'source': 'ssh',
            'event_type': 'Failed login',
            'ip': '192.168.1.50',
            'status': 'failed',
            'message': 'Failed password for admin from 192.168.1.50 port 45235 ssh2',
            'username': 'admin',
            'event_id': 2,
        },
        {
            'timestamp': '2026-08-12 15:01:00',
            'source': 'ssh',
            'event_type': 'Failed login',
            'ip': '192.168.1.50',
            'status': 'failed',
            'message': 'Failed password for admin from 192.168.1.50 port 45236 ssh2',
            'username': 'admin',
            'event_id': 3,
        },
        {
            'timestamp': '2026-08-12 15:01:30',
            'source': 'ssh',
            'event_type': 'Failed login',
            'ip': '192.168.1.50',
            'status': 'failed',
            'message': 'Failed password for admin from 192.168.1.50 port 45237 ssh2',
            'username': 'admin',
            'event_id': 4,
        },
        {
            'timestamp': '2026-08-12 15:02:00',
            'source': 'ssh',
            'event_type': 'Failed login',
            'ip': '192.168.1.50',
            'status': 'failed',
            'message': 'Failed password for admin from 192.168.1.50 port 45238 ssh2',
            'username': 'admin',
            'event_id': 5,
        },
    ]

    print(detector.detect(sample_logs))
    print(detector.detect_summary(sample_logs))
