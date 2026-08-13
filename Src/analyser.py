"""Main log analysis orchestrator."""

from typing import Any, Dict, List, Optional
from datetime import datetime

from Src.Parsers.ssh import SSHLogParser
from Src.Parsers.apache import ApacheLogParser
from Src.Parsers.firewall import FirewallLogParser
from Src.Parsers.windows import WindowsLogParser

from Src.Detection.failed_logins import FailedLoginDetector
from Src.Detection.brute_force import BruteForceDetector
from Src.Detection.suspicious_IP import SuspiciousIPDetector

from Src.timeline import Timeline
from Src.reports import ReportGenerator


class LogAnalyser:
    """Orchestrate log parsing, detection, and reporting."""

    def __init__(self):
        """Initialize all parsers and detectors."""
        # Initialize parsers
        self.ssh_parser = SSHLogParser()
        self.apache_parser = ApacheLogParser()
        self.firewall_parser = FirewallLogParser()
        self.windows_parser = WindowsLogParser()

        # Initialize detectors
        self.failed_login_detector = FailedLoginDetector()
        self.brute_force_detector = BruteForceDetector()
        self.suspicious_ip_detector = SuspiciousIPDetector()

        # Initialize timeline and report generator
        self.timeline = Timeline()
        self.report_generator = ReportGenerator()

        # Storage for parsed logs and alerts
        self.parsed_logs: List[Dict[str, Any]] = []
        self.failed_login_alerts: List[Dict[str, Any]] = []
        self.brute_force_alerts: List[Dict[str, Any]] = []
        self.suspicious_ip_alerts: List[Dict[str, Any]] = []

    def parse_ssh_log_file(self, filepath: str) -> int:
        """
        Parse an SSH log file.

        Returns:
            Number of successfully parsed log lines
        """
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    parsed_log = self.ssh_parser.parse_line(line.strip())
                    if parsed_log:
                        self.parsed_logs.append(parsed_log)
                        count += 1
        except Exception as e:
            print(f"Error parsing SSH log file {filepath}: {e}")

        return count

    def parse_apache_log_file(self, filepath: str, log_type: str = 'access') -> int:
        """
        Parse an Apache log file.

        Args:
            filepath: Path to the log file
            log_type: 'access' or 'error'

        Returns:
            Number of successfully parsed log lines
        """
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    parsed_log = self.apache_parser.parse_line(line.strip(), log_type)
                    if parsed_log:
                        self.parsed_logs.append(parsed_log)
                        count += 1
        except Exception as e:
            print(f"Error parsing Apache log file {filepath}: {e}")

        return count

    def parse_firewall_log_file(self, filepath: str, log_type: str = 'auto') -> int:
        """
        Parse a firewall log file.

        Args:
            filepath: Path to the log file
            log_type: 'iptables', 'pfsense', 'syslog', or 'auto'

        Returns:
            Number of successfully parsed log lines
        """
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    parsed_log = self.firewall_parser.parse_line(line.strip(), log_type)
                    if parsed_log:
                        self.parsed_logs.append(parsed_log)
                        count += 1
        except Exception as e:
            print(f"Error parsing firewall log file {filepath}: {e}")

        return count

    def parse_windows_log_file(self, filepath: str) -> int:
        """
        Parse a Windows event log file.

        Returns:
            Number of successfully parsed log lines
        """
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    parsed_log = self.windows_parser.parse_line(line.strip())
                    if parsed_log:
                        self.parsed_logs.append(parsed_log)
                        count += 1
        except Exception as e:
            print(f"Error parsing Windows log file {filepath}: {e}")

        return count

    def run_detection(self) -> None:
        """Run all detection engines on parsed logs."""
        # Detect failed logins
        self.failed_login_alerts = self.failed_login_detector.detect(self.parsed_logs)

        # Detect brute force attacks
        self.brute_force_alerts = self.brute_force_detector.detect(self.parsed_logs)

        # Detect suspicious IPs
        self.suspicious_ip_alerts = self.suspicious_ip_detector.detect(self.parsed_logs)

    def compile_timeline(self) -> Timeline:
        """
        Compile all alerts into a timeline.

        Returns:
            Populated Timeline object
        """
        self.timeline.clear()

        # Add all alerts to timeline
        if self.failed_login_alerts:
            self.timeline.add_events(self.failed_login_alerts)

        if self.brute_force_alerts:
            self.timeline.add_events(self.brute_force_alerts)

        if self.suspicious_ip_alerts:
            self.timeline.add_events(self.suspicious_ip_alerts)

        return self.timeline

    def generate_report(self, output_path: str = 'reports/security_report.html') -> bool:
        """
        Generate an HTML security report.

        Returns:
            True if report was generated successfully
        """
        # Compile timeline
        self.compile_timeline()
        timeline_events = self.timeline.get_sorted_timeline()

        # Generate report
        return self.report_generator.generate_report(
            timeline_events=timeline_events,
            suspicious_ips=self.suspicious_ip_alerts,
            output_path=output_path
        )

    def save_timeline(self, filepath: str = 'reports/timeline.txt') -> bool:
        """
        Save the timeline to a text file.

        Returns:
            True if save was successful
        """
        try:
            self.compile_timeline()
            return self.timeline.save_to_file(filepath)
        except Exception as e:
            print(f"Error saving timeline: {e}")
            return False

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get a summary of the analysis results."""
        return {
            'total_logs_parsed': len(self.parsed_logs),
            'failed_login_alerts': len(self.failed_login_alerts),
            'brute_force_alerts': len(self.brute_force_alerts),
            'suspicious_ip_alerts': len(self.suspicious_ip_alerts),
            'timeline_events': len(self.timeline.get_sorted_timeline()) if self.timeline else 0,
            'unique_ips': len(self.suspicious_ip_alerts),
        }


if __name__ == '__main__':
    # Example usage
    analyser = LogAnalyser()

    print("=" * 60)
    print("Log Analysis Tool - Analyser Module")
    print("=" * 60)
    print("\nThis module orchestrates the entire analysis pipeline.")
    print("Import it in main.py to use the full analysis workflow.")