"""Timeline generator for security events and alerts from the analysis window."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from collections import defaultdict


class Timeline:
    """Create and manage a chronological timeline of all detected security events and alerts."""

    def __init__(self):
        """Initialize an empty timeline."""
        self.events: List[Dict[str, Any]] = []

    @staticmethod
    def _parse_timestamp(value: Any) -> Optional[datetime]:
        """Parse various timestamp formats from alerts."""
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

    def add_events(self, events: List[Dict[str, Any]]) -> None:
        """
        Add a list of events/alerts to the timeline.

        Args:
            events: List of alert dictionaries containing at minimum:
                    - timestamp: Event timestamp
                    - alert_type: Type of alert
                    - ip: Source IP address
                    - severity: Alert severity level
        """
        if not events:
            return

        for event in events:
            if isinstance(event, dict):
                self.events.append(event)

    def add_single_event(self, event: Dict[str, Any]) -> None:
        """Add a single event to the timeline."""
        if isinstance(event, dict):
            self.events.append(event)

    def get_sorted_timeline(self) -> List[Dict[str, Any]]:
        """
        Return all events sorted chronologically by timestamp.

        Returns:
            List of events sorted from earliest to latest timestamp.
        """
        sorted_events = sorted(
            self.events,
            key=lambda e: self._parse_timestamp(e.get('timestamp')) or datetime.min
        )
        return sorted_events

    def get_timeline_by_severity(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Return timeline events grouped by severity level.

        Returns:
            Dictionary with severity levels as keys and lists of events as values.
        """
        severity_groups = defaultdict(list)
        sorted_events = self.get_sorted_timeline()

        for event in sorted_events:
            severity = event.get('severity', 'unknown').lower()
            severity_groups[severity].append(event)

        return dict(severity_groups)

    def get_timeline_by_type(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Return timeline events grouped by alert type.

        Returns:
            Dictionary with alert types as keys and lists of events as values.
        """
        type_groups = defaultdict(list)
        sorted_events = self.get_sorted_timeline()

        for event in sorted_events:
            alert_type = event.get('alert_type', 'Unknown')
            type_groups[alert_type].append(event)

        return dict(type_groups)

    def get_timeline_by_source(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Return timeline events grouped by source.

        Returns:
            Dictionary with source names as keys and lists of events as values.
        """
        source_groups = defaultdict(list)
        sorted_events = self.get_sorted_timeline()

        for event in sorted_events:
            source = event.get('source', 'unknown')
            source_groups[source].append(event)

        return dict(source_groups)

    def format_as_text(self) -> str:
        """
        Format the timeline as human-readable text.

        Returns:
            Formatted text representation of the timeline.
        """
        sorted_events = self.get_sorted_timeline()

        if not sorted_events:
            return "No events recorded in analysis window.\n"

        lines = ["=" * 100]
        lines.append("SECURITY EVENT TIMELINE")
        lines.append("=" * 100)
        lines.append("")

        event_count = len(sorted_events)
        lines.append(f"Total Events: {event_count}\n")

        for idx, event in enumerate(sorted_events, 1):
            timestamp = event.get('timestamp', 'N/A')
            alert_type = event.get('alert_type', 'Unknown')
            ip = event.get('ip', 'N/A')
            severity = event.get('severity', 'unknown').upper()
            source = event.get('source', 'N/A')
            username = event.get('username', 'N/A')
            message = event.get('message', '')

            lines.append(f"[{idx}] {timestamp}")
            lines.append(f"    Alert Type: {alert_type}")
            lines.append(f"    Source: {source}")
            lines.append(f"    Severity: {severity}")
            lines.append(f"    IP Address: {ip}")

            if username and username != 'N/A':
                lines.append(f"    Username: {username}")

            if message:
                lines.append(f"    Message: {message}")

            event_id = event.get('event_id')
            if event_id:
                lines.append(f"    Event ID: {event_id}")

            lines.append("")

        return "\n".join(lines)

    def save_to_file(self, filepath: str) -> bool:
        """
        Save the formatted timeline to a text file.

        Args:
            filepath: Path to save the timeline file.

        Returns:
            True if save was successful, False otherwise.
        """
        try:
            timeline_text = self.format_as_text()
            with open(filepath, 'w') as f:
                f.write(timeline_text)
            return True
        except Exception as e:
            print(f"Error saving timeline to {filepath}: {e}")
            return False

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate a summary of the timeline.

        Returns:
            Dictionary containing timeline statistics.
        """
        sorted_events = self.get_sorted_timeline()

        if not sorted_events:
            return {
                'total_events': 0,
                'event_types': {},
                'sources': {},
                'severity_breakdown': {},
                'ips_involved': [],
            }

        # Count by type
        type_counts = defaultdict(int)
        source_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        ips_involved = set()

        for event in sorted_events:
            type_counts[event.get('alert_type', 'Unknown')] += 1
            source_counts[event.get('source', 'unknown')] += 1
            severity_counts[event.get('severity', 'unknown')] += 1

            ip = event.get('ip', '')
            if ip:
                ips_involved.add(ip)

        return {
            'total_events': len(sorted_events),
            'event_types': dict(sorted(type_counts.items(), key=lambda x: x[1], reverse=True)),
            'sources': dict(sorted(source_counts.items())),
            'severity_breakdown': dict(sorted(severity_counts.items())),
            'ips_involved': sorted(list(ips_involved)),
            'earliest_event': sorted_events[0].get('timestamp') if sorted_events else None,
            'latest_event': sorted_events[-1].get('timestamp') if sorted_events else None,
        }

    def clear(self) -> None:
        """Clear all events from the timeline."""
        self.events = []


if __name__ == '__main__':
    # Example usage
    timeline = Timeline()

    sample_alerts = [
        {
            'alert_type': 'Failed login',
            'timestamp': '2026-08-12 15:03:00',
            'source': 'ssh',
            'ip': '192.168.1.50',
            'username': 'admin',
            'severity': 'medium',
            'message': 'Failed password attempt',
        },
        {
            'alert_type': 'Brute force attack',
            'timestamp': '2026-08-12 15:05:30',
            'source': 'ssh',
            'ip': '192.168.1.50',
            'severity': 'high',
            'message': '5 failed logins detected within 300 seconds',
        },
        {
            'alert_type': 'Failed login',
            'timestamp': '2026-08-12 15:10:00',
            'source': 'windows',
            'ip': '10.0.0.12',
            'username': 'svcuser',
            'severity': 'medium',
            'message': 'Failed account logon',
        },
    ]

    timeline.add_events(sample_alerts)
    print(timeline.format_as_text())
    print("\nSummary:")
    print(timeline.get_summary())