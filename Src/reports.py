"""HTML report generator for security analysis results using Jinja2 templating."""

import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import defaultdict

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:
    raise ImportError("Jinja2 is required for HTML report generation. Install it with: pip install Jinja2")


class ReportGenerator:
    """Generate HTML security analysis reports using Jinja2 templates."""

    def __init__(self, template_dir: str = None):
        """
        Initialize the report generator with template directory.

        Args:
            template_dir: Path to the Templates directory. If None, uses relative path.
        """
        if template_dir is None:
            # Default to Templates folder relative to this file
            template_dir = os.path.join(os.path.dirname(__file__), '..', 'Templates')

        self.template_dir = os.path.abspath(template_dir)

        if not os.path.exists(self.template_dir):
            raise FileNotFoundError(f"Template directory not found: {self.template_dir}")

        # Initialize Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

    def generate_report(
        self,
        timeline_events: List[Dict[str, Any]],
        suspicious_ips: List[Dict[str, Any]] = None,
        analysis_start: str = None,
        analysis_end: str = None,
        output_path: str = 'reports/security_report.html'
    ) -> bool:
        """
        Generate an HTML security report from timeline events and suspicious IPs.

        Args:
            timeline_events: List of event/alert dictionaries from the timeline
            suspicious_ips: List of suspicious IP dictionaries with risk levels and scores
            analysis_start: Start timestamp of the analysis period
            analysis_end: End timestamp of the analysis period
            output_path: Output path for the HTML report file

        Returns:
            True if report was generated successfully, False otherwise
        """
        try:
            # Calculate analysis period
            if analysis_start is None or analysis_end is None:
                analysis_start, analysis_end = self._extract_analysis_period(timeline_events)

            # Compile summary statistics
            summary = self._compile_summary(timeline_events, suspicious_ips)

            # Get top suspicious IPs
            top_ips = self._get_top_suspicious_ips(suspicious_ips, top_n=10)

            # Generate chart data
            chart_data = {
                'events_over_time': self._generate_events_over_time_chart(timeline_events),
                'events_by_type': self._generate_events_by_type_chart(timeline_events),
                'events_by_severity': self._generate_events_by_severity_chart(timeline_events),
                'top_ips': self._generate_top_ips_chart(suspicious_ips, top_n=5),
            }

            # Prepare context for template
            context = {
                'analysis_start': analysis_start or 'N/A',
                'analysis_end': analysis_end or 'N/A',
                'report_generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'summary': summary,
                'top_suspicious_ips': top_ips,
                'timeline_events': timeline_events or [],
                'chart_data': chart_data,
            }

            # Render template
            template = self.env.get_template('report.html')
            html_content = template.render(context)

            # Write to file
            return self._write_report(html_content, output_path)

        except Exception as e:
            print(f"Error generating report: {e}")
            return False

    @staticmethod
    def _extract_analysis_period(timeline_events: List[Dict[str, Any]]) -> tuple:
        """
        Extract the earliest and latest timestamps from the timeline.

        Returns:
            Tuple of (start_timestamp, end_timestamp)
        """
        if not timeline_events:
            return None, None

        timestamps = [
            event.get('timestamp') for event in timeline_events
            if event.get('timestamp')
        ]

        if not timestamps:
            return None, None

        # Simple string sorting works if timestamps are in ISO format
        sorted_timestamps = sorted(timestamps)
        return sorted_timestamps[0], sorted_timestamps[-1]

    @staticmethod
    def _compile_summary(
        timeline_events: List[Dict[str, Any]],
        suspicious_ips: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Compile summary statistics from events and IPs.

        Returns:
            Dictionary with summary statistics
        """
        summary = {
            'total_events': len(timeline_events) if timeline_events else 0,
            'total_suspicious_ips': len(suspicious_ips) if suspicious_ips else 0,
            'critical_events': 0,
            'total_sources': 0,
            'alert_types': defaultdict(int),
            'severity_breakdown': defaultdict(int),
            'sources': defaultdict(int),
        }

        if timeline_events:
            sources_set = set()

            for event in timeline_events:
                # Count by alert type
                alert_type = event.get('alert_type', 'Unknown')
                summary['alert_types'][alert_type] += 1

                # Count by severity
                severity = event.get('severity', 'unknown').lower()
                summary['severity_breakdown'][severity] += 1

                if severity == 'high':
                    summary['critical_events'] += 1

                # Count by source
                source = event.get('source', 'unknown')
                summary['sources'][source] += 1
                sources_set.add(source)

            summary['total_sources'] = len(sources_set)

        # Convert defaultdicts to regular dicts
        summary['alert_types'] = dict(sorted(summary['alert_types'].items()))
        summary['severity_breakdown'] = dict(sorted(summary['severity_breakdown'].items()))
        summary['sources'] = dict(sorted(summary['sources'].items()))

        return summary

    @staticmethod
    def _get_top_suspicious_ips(
        suspicious_ips: List[Dict[str, Any]],
        top_n: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get the top N most suspicious IP addresses.

        Args:
            suspicious_ips: List of suspicious IP dictionaries
            top_n: Number of top IPs to return

        Returns:
            List of top suspicious IPs, sorted by score (descending)
        """
        if not suspicious_ips:
            return []

        # Sort by score (descending)
        sorted_ips = sorted(
            suspicious_ips,
            key=lambda x: x.get('score', 0),
            reverse=True
        )

        # Add violation count for each IP (count of alerts)
        for ip_info in sorted_ips:
            if 'violation_count' not in ip_info:
                ip_info['violation_count'] = 1

        return sorted_ips[:top_n]

    @staticmethod
    def _parse_timestamp(value: Any) -> Optional[datetime]:
        """Parse various timestamp formats."""
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

    @staticmethod
    def _generate_events_over_time_chart(
        timeline_events: List[Dict[str, Any]]
    ) -> Dict[str, List]:
        """
        Generate data for events over time chart (hourly bins).

        Returns:
            Dictionary with labels and data for chart
        """
        if not timeline_events:
            return {'labels': [], 'data': []}

        # Parse all timestamps and create hourly bins
        hourly_counts = defaultdict(int)

        for event in timeline_events:
            timestamp = ReportGenerator._parse_timestamp(event.get('timestamp'))
            if timestamp:
                # Create hourly bucket (round down to nearest hour)
                hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
                hourly_counts[hour_key] += 1

        # Sort by time
        sorted_hours = sorted(hourly_counts.keys())

        if not sorted_hours:
            return {'labels': [], 'data': []}

        # Fill gaps with zeros
        labels = []
        data = []
        current = sorted_hours[0]
        end = sorted_hours[-1]

        while current <= end:
            labels.append(current.strftime('%Y-%m-%d %H:00'))
            data.append(hourly_counts.get(current, 0))
            current += timedelta(hours=1)

        return {'labels': labels, 'data': data}

    @staticmethod
    def _generate_events_by_type_chart(
        timeline_events: List[Dict[str, Any]]
    ) -> Dict[str, List]:
        """
        Generate data for events by type chart.

        Returns:
            Dictionary with labels and data for chart
        """
        type_counts = defaultdict(int)

        for event in timeline_events:
            alert_type = event.get('alert_type', 'Unknown')
            type_counts[alert_type] += 1

        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)

        labels = [label for label, _ in sorted_types]
        data = [count for _, count in sorted_types]

        return {'labels': labels, 'data': data}

    @staticmethod
    def _generate_events_by_severity_chart(
        timeline_events: List[Dict[str, Any]]
    ) -> Dict[str, List]:
        """
        Generate data for events by severity chart.

        Returns:
            Dictionary with labels and data for chart
        """
        severity_counts = defaultdict(int)

        for event in timeline_events:
            severity = event.get('severity', 'unknown').lower()
            severity_counts[severity] += 1

        # Order by severity level
        severity_order = ['critical', 'high', 'medium', 'low', 'unknown']
        labels = []
        data = []

        for severity in severity_order:
            if severity in severity_counts:
                labels.append(severity.capitalize())
                data.append(severity_counts[severity])

        return {'labels': labels, 'data': data}

    @staticmethod
    def _generate_top_ips_chart(
        suspicious_ips: List[Dict[str, Any]],
        top_n: int = 5
    ) -> Dict[str, List]:
        """
        Generate data for top IPs by risk score chart.

        Returns:
            Dictionary with labels and data for chart
        """
        if not suspicious_ips:
            return {'labels': [], 'data': []}

        sorted_ips = sorted(
            suspicious_ips,
            key=lambda x: x.get('score', 0),
            reverse=True
        )

        top_ips = sorted_ips[:top_n]
        labels = [ip.get('ip', 'Unknown') for ip in top_ips]
        data = [ip.get('score', 0) for ip in top_ips]

        return {'labels': labels, 'data': data}

    @staticmethod
    def _write_report(html_content: str, output_path: str) -> bool:
        """
        Write HTML report to file.

        Args:
            html_content: HTML content to write
            output_path: Output file path

        Returns:
            True if successful, False otherwise
        """
        try:
            # Create output directory if it doesn't exist
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            # Write report
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            print(f"Report successfully generated: {output_path}")
            return True

        except Exception as e:
            print(f"Error writing report to {output_path}: {e}")
            return False


class ReportCompiler:
    """Compile results from all detection engines and timeline into a single report."""

    def __init__(self, report_generator: ReportGenerator = None):
        """
        Initialize the report compiler.

        Args:
            report_generator: ReportGenerator instance. Creates new one if None.
        """
        if report_generator is None:
            report_generator = ReportGenerator()

        self.report_generator = report_generator

    def compile_and_generate(
        self,
        failed_login_alerts: List[Dict[str, Any]] = None,
        brute_force_alerts: List[Dict[str, Any]] = None,
        suspicious_ip_data: List[Dict[str, Any]] = None,
        timeline_events: List[Dict[str, Any]] = None,
        analysis_start: str = None,
        analysis_end: str = None,
        output_path: str = 'reports/security_report.html'
    ) -> bool:
        """
        Compile alerts from all detection engines and generate a comprehensive report.

        Args:
            failed_login_alerts: List of failed login alerts
            brute_force_alerts: List of brute force attack alerts
            suspicious_ip_data: List of suspicious IP data with risk classifications
            timeline_events: Pre-compiled timeline events (overrides individual alerts)
            analysis_start: Analysis period start timestamp
            analysis_end: Analysis period end timestamp
            output_path: Output path for the HTML report

        Returns:
            True if report generated successfully
        """
        # Compile all alerts if timeline_events not provided
        if timeline_events is None:
            all_alerts = []

            if failed_login_alerts:
                all_alerts.extend(failed_login_alerts)

            if brute_force_alerts:
                all_alerts.extend(brute_force_alerts)

            # Sort by timestamp
            timeline_events = sorted(
                all_alerts,
                key=lambda e: e.get('timestamp', '')
            )

        # Generate report
        return self.report_generator.generate_report(
            timeline_events=timeline_events,
            suspicious_ips=suspicious_ip_data,
            analysis_start=analysis_start,
            analysis_end=analysis_end,
            output_path=output_path
        )


if __name__ == '__main__':
    # Example usage
    sample_events = [
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

    sample_suspicious_ips = [
        {
            'ip': '192.168.1.50',
            'score': 7,
            'risk_level': 'critical risk',
            'violation_count': 2,
        },
        {
            'ip': '10.0.0.12',
            'score': 3,
            'risk_level': 'caution risk',
            'violation_count': 1,
        },
    ]

    # Generate report
    generator = ReportGenerator()
    success = generator.generate_report(
        timeline_events=sample_events,
        suspicious_ips=sample_suspicious_ips,
        analysis_start='2026-08-12 15:00:00',
        analysis_end='2026-08-12 16:00:00',
        output_path='reports/security_report.html'
    )

    if success:
        print("Report generated successfully!")
    else:
        print("Failed to generate report.")