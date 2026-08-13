"""Detection engine for suspicious IP address scoring."""

from collections import defaultdict
from typing import Any, Dict, List


class SuspiciousIPDetector:
    """Score IP addresses by suspicious activity and classify their risk."""

    # Risk scoring from the README
    FAILED_LOGIN_SCORE = 1
    BRUTE_FORCE_SCORE = 5
    OPEN_PORT_SCAN_SCORE = 5
    FIREWALL_DENY_SCORE = 1
    WEB_ATTACK_SCORE = 3

    @staticmethod
    def _risk_level(score: int) -> str:
        """Map a risk score to the README's category settings."""
        if score <= 2:
            return 'no risk'
        if score <= 6:
            return 'caution risk'
        return 'critical risk'

    @staticmethod
    def _matches_failed_login(log: Dict[str, Any]) -> bool:
        event_type = str(log.get('event_type', '')).lower()
        status = str(log.get('status', '')).lower()
        message = str(log.get('message', '')).lower()

        return (
            'failed login' in event_type or
            'failed logon' in event_type or
            'failed password' in event_type or
            status == 'failed' or
            status == 'invalid_user' or
            'failed password' in message
        )

    @staticmethod
    def _matches_brute_force(log: Dict[str, Any]) -> bool:
        event_type = str(log.get('event_type', '')).lower()
        message = str(log.get('message', '')).lower()

        return (
            'brute force' in event_type or
            'brute-force' in event_type or
            'failed logins from' in message or
            '5 failed logins' in message
        )

    @staticmethod
    def _matches_port_scan(log: Dict[str, Any]) -> bool:
        event_type = str(log.get('event_type', '')).lower()
        status = str(log.get('status', '')).lower()
        message = str(log.get('message', '')).lower()

        return (
            'port scan' in event_type or
            'portscan' in event_type or
            'open port' in event_type or
            status == 'scan' or
            'nmap' in message or
            'port scan' in message
        )

    @staticmethod
    def _matches_firewall_deny(log: Dict[str, Any]) -> bool:
        event_type = str(log.get('event_type', '')).lower()
        status = str(log.get('status', '')).lower()
        message = str(log.get('message', '')).lower()

        return (
            'firewall deny' in event_type or
            'firewall denied' in event_type or
            'deny' in status or
            'denied' in message or
            'firewall' in event_type and 'deny' in message
        )

    @staticmethod
    def _matches_web_attack(log: Dict[str, Any]) -> bool:
        event_type = str(log.get('event_type', '')).lower()
        message = str(log.get('message', '')).lower()

        return (
            'web attack' in event_type or
            'sql injection' in event_type or
            'xss' in event_type or
            'web attack pattern' in event_type or
            'sql injection' in message or
            'xss' in message or
            'command injection' in message or
            'path traversal' in message
        )

    def detect(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score each IP address based on suspicious activity and classify its risk."""
        scores: Dict[str, int] = defaultdict(int)
        reasons: Dict[str, List[str]] = defaultdict(list)

        for log in logs or []:
            if not isinstance(log, dict):
                continue

            ip = str(log.get('ip', '')).strip()
            if not ip:
                continue

            event_type = str(log.get('event_type', '')).lower()
            message = str(log.get('message', '')).lower()
            score_delta = 0
            reason = []

            if self._matches_failed_login(log):
                score_delta += self.FAILED_LOGIN_SCORE
                reason.append('failed login')

            if self._matches_brute_force(log):
                score_delta += self.BRUTE_FORCE_SCORE
                reason.append('brute force attack')

            if self._matches_port_scan(log):
                score_delta += self.OPEN_PORT_SCAN_SCORE
                reason.append('port scan')

            if self._matches_firewall_deny(log):
                score_delta += self.FIREWALL_DENY_SCORE
                reason.append('firewall deny')

            if self._matches_web_attack(log):
                score_delta += self.WEB_ATTACK_SCORE
                reason.append('web attack pattern')

            if not reason:
                continue

            scores[ip] += score_delta
            reasons[ip].extend(reason)

        alerts: List[Dict[str, Any]] = []
        for ip, score in sorted(scores.items()):
            risk_level = self._risk_level(score)
            alerts.append({
                'alert_type': 'Suspicious IP',
                'ip': ip,
                'score': score,
                'risk_level': risk_level,
                'reasons': sorted(set(reasons.get(ip, []))),
                'severity': 'low' if risk_level == 'no risk' else 'medium' if risk_level == 'caution risk' else 'high',
            })

        return alerts

    def detect_summary(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Count suspicious IPs by their assigned risk category."""
        alerts = self.detect(logs)
        counts = defaultdict(int)

        for alert in alerts:
            counts[alert.get('risk_level', 'no risk')] += 1

        return {
            'total_suspicious_ips': len(alerts),
            'suspicious_ips_by_risk': dict(sorted(counts.items())),
            'suspicious_ip_scores': {
                alert.get('ip', ''): alert.get('score', 0)
                for alert in alerts
            },
        }


if __name__ == '__main__':
    detector = SuspiciousIPDetector()
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
            'timestamp': '2026-08-12 15:01:00',
            'source': 'ssh',
            'event_type': 'Failed login',
            'ip': '192.168.1.50',
            'status': 'failed',
            'message': 'Failed password for admin from 192.168.1.50 port 45235 ssh2',
            'username': 'admin',
            'event_id': 2,
        },
        {
            'timestamp': '2026-08-12 15:02:00',
            'source': 'ssh',
            'event_type': 'Failed login',
            'ip': '192.168.1.50',
            'status': 'failed',
            'message': 'Failed password for admin from 192.168.1.50 port 45236 ssh2',
            'username': 'admin',
            'event_id': 3,
        },
        {
            'timestamp': '2026-08-12 15:03:00',
            'source': 'ssh',
            'event_type': 'Failed login',
            'ip': '192.168.1.50',
            'status': 'failed',
            'message': 'Failed password for admin from 192.168.1.50 port 45237 ssh2',
            'username': 'admin',
            'event_id': 4,
        },
        {
            'timestamp': '2026-08-12 15:04:00',
            'source': 'ssh',
            'event_type': 'Failed login',
            'ip': '192.168.1.50',
            'status': 'failed',
            'message': 'Failed password for admin from 192.168.1.50 port 45238 ssh2',
            'username': 'admin',
            'event_id': 5,
        },
        {
            'timestamp': '2026-08-12 15:05:00',
            'source': 'firewall',
            'event_type': 'Firewall deny',
            'ip': '192.168.1.50',
            'status': 'deny',
            'message': 'Firewall deny for host 192.168.1.50',
            'username': '',
            'event_id': 6,
        },
        {
            'timestamp': '2026-08-12 15:06:00',
            'source': 'apache',
            'event_type': 'Web attack pattern',
            'ip': '203.0.113.10',
            'status': '403',
            'message': 'SQL injection attempt from 203.0.113.10',
            'username': '',
            'event_id': 7,
        },
    ]

    print(detector.detect(sample_logs))
    print(detector.detect_summary(sample_logs))
