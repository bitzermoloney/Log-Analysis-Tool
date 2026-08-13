"""Main entry point for the Log Analysis Tool."""

import os
import sys
import argparse
from datetime import datetime
from pathlib import Path

# Ensure we can import from the parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Src.analyser import LogAnalyser


def setup_directories():
    """Create necessary directories if they don't exist."""
    directories = ['data', 'reports', 'data/logs']

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)


def print_header():
    """Print the tool header."""
    print("\n" + "=" * 70)
    print("🛡️  LOG ANALYSIS TOOL - SIEM-Style Security Log Analyzer".center(70))
    print("=" * 70 + "\n")


def print_summary(summary: dict):
    """Print analysis summary in a formatted way."""
    print("\n" + "-" * 70)
    print("ANALYSIS SUMMARY".center(70))
    print("-" * 70)
    print(f"  📊 Total Logs Parsed:        {summary['total_logs_parsed']}")
    print(f"  ❌ Failed Login Alerts:      {summary['failed_login_alerts']}")
    print(f"  🔨 Brute Force Alerts:       {summary['brute_force_alerts']}")
    print(f"  🚨 Suspicious IP Alerts:     {summary['suspicious_ip_alerts']}")
    print(f"  📈 Timeline Events:          {summary['timeline_events']}")
    print("-" * 70 + "\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Log Analysis Tool - SIEM-style threat detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --ssh /var/log/auth.log
  %(prog)s --apache /var/log/apache2/access.log --apache /var/log/apache2/error.log
  %(prog)s --firewall /var/log/firewall.log --windows /var/log/windows.log
  %(prog)s --ssh /var/log/auth.log --report output.html --timeline timeline.txt
        """
    )

    parser.add_argument('--ssh', help='Path to SSH log file', action='append')
    parser.add_argument('--apache', help='Path to Apache log file', action='append')
    parser.add_argument('--firewall', help='Path to firewall log file', action='append')
    parser.add_argument('--windows', help='Path to Windows event log file', action='append')
    parser.add_argument(
        '--report',
        help='Output HTML report path (default: reports/security_report.html)',
        default='reports/security_report.html'
    )
    parser.add_argument(
        '--timeline',
        help='Output timeline text file path (default: reports/timeline.txt)',
        default='reports/timeline.txt'
    )
    parser.add_argument(
        '--demo',
        help='Run with demo data (sample analysis)',
        action='store_true'
    )

    args = parser.parse_args()

    # Setup directories
    setup_directories()

    # Print header
    print_header()

    # Initialize analyser
    analyser = LogAnalyser()

    # If demo mode, create and use demo data
    if args.demo:
        print("📋 Running in DEMO mode with sample data...\n")
        _run_demo_analysis(analyser)
    else:
        # Parse log files
        total_parsed = 0

        if args.ssh:
            for ssh_file in args.ssh:
                if os.path.exists(ssh_file):
                    count = analyser.parse_ssh_log_file(ssh_file)
                    print(f"✅ Parsed SSH log: {ssh_file} ({count} entries)")
                    total_parsed += count
                else:
                    print(f"❌ SSH log file not found: {ssh_file}")

        if args.apache:
            for apache_file in args.apache:
                if os.path.exists(apache_file):
                    log_type = 'error' if 'error' in apache_file.lower() else 'access'
                    count = analyser.parse_apache_log_file(apache_file, log_type)
                    print(f"✅ Parsed Apache log ({log_type}): {apache_file} ({count} entries)")
                    total_parsed += count
                else:
                    print(f"❌ Apache log file not found: {apache_file}")

        if args.firewall:
            for fw_file in args.firewall:
                if os.path.exists(fw_file):
                    count = analyser.parse_firewall_log_file(fw_file)
                    print(f"✅ Parsed firewall log: {fw_file} ({count} entries)")
                    total_parsed += count
                else:
                    print(f"❌ Firewall log file not found: {fw_file}")

        if args.windows:
            for win_file in args.windows:
                if os.path.exists(win_file):
                    count = analyser.parse_windows_log_file(win_file)
                    print(f"✅ Parsed Windows log: {win_file} ({count} entries)")
                    total_parsed += count
                else:
                    print(f"❌ Windows log file not found: {win_file}")

        if total_parsed == 0:
            print("⚠️  No log files specified or no entries parsed.")
            print("Use --help to see available options or --demo for a demo analysis.\n")
            return

    # Run detection
    print("\n🔍 Running threat detection engines...")
    analyser.run_detection()

    # Compile timeline
    print("📅 Compiling timeline...")
    analyser.compile_timeline()

    # Generate HTML report
    print(f"📊 Generating HTML report: {args.report}")
    if analyser.generate_report(args.report):
        print(f"   ✅ Report saved to {args.report}")
    else:
        print(f"   ❌ Failed to generate report")

    # Save timeline
    print(f"📝 Saving timeline: {args.timeline}")
    if analyser.save_timeline(args.timeline):
        print(f"   ✅ Timeline saved to {args.timeline}")
    else:
        print(f"   ❌ Failed to save timeline")

    # Print summary
    summary = analyser.get_analysis_summary()
    print_summary(summary)

    print(f"✨ Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def _run_demo_analysis(analyser: LogAnalyser):
    """Run a demo analysis with sample data."""
    from datetime import timedelta

    # Create sample logs
    base_time = datetime(2026, 8, 12, 15, 0, 0)
    sample_logs = []

    # Generate 50 sample events with various types
    event_types = ['Failed login', 'Brute force attack', 'Port scan', 'Firewall deny', 'Web attack']
    sources = ['ssh', 'apache', 'firewall', 'windows']
    severities = ['high', 'medium', 'low']
    ips = [
        '192.168.1.50', '192.168.1.51', '10.0.0.12',
        '172.16.0.5', '203.0.113.42', '198.51.100.88'
    ]

    for i in range(50):
        event_time = base_time + timedelta(minutes=i * 2)

        sample_logs.append({
            'alert_type': event_types[i % len(event_types)],
            'timestamp': event_time.strftime('%Y-%m-%d %H:%M:%S'),
            'source': sources[i % len(sources)],
            'ip': ips[i % len(ips)],
            'username': f'user{i % 5}' if i % 5 != 0 else 'admin',
            'severity': severities[i % len(severities)],
            'message': f'Demo event {i}: Suspicious activity detected',
            'event_id': 1000 + i,
            'status': 'failed' if 'Failed' in event_types[i % len(event_types)] else 'active',
        })

    # Simulate parsed logs
    analyser.parsed_logs = sample_logs

    # Run detection
    analyser.run_detection()

    # Print summary
    summary = analyser.get_analysis_summary()
    print_summary(summary)

    # Generate report
    print(f"📊 Generating demo HTML report: reports/security_report.html")
    if analyser.generate_report('reports/security_report.html'):
        print(f"   ✅ Report saved")
    else:
        print(f"   ❌ Failed to generate report")

    # Save timeline
    print(f"📝 Saving demo timeline: reports/timeline.txt")
    if analyser.save_timeline('reports/timeline.txt'):
        print(f"   ✅ Timeline saved")
    else:
        print(f"   ❌ Failed to save timeline")


if __name__ == '__main__':
    main()