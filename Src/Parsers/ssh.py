"""
SSH Log Parser

Parses SSH logs (OpenSSH, syslog auth.log, secure) into a normalized log format.
Supports multiple SSH log formats and detects various authentication events.

Normalized log structure:
{
    'timestamp': str,       # YYYY-MM-DD HH:MM:SS
    'source': str,          # 'ssh'
    'event_type': str,      # 'Login attempt', 'Failed login', 'Invalid user', etc.
    'ip': str,              # Source IP address
    'status': str,          # 'success', 'failed', 'invalid_user', etc.
    'message': str,         # Log details
    'username': str,        # Username attempting login
    'event_id': int         # Unique identifier
}
"""

import re
from datetime import datetime
from typing import Dict, List, Optional


class SSHLogParser:
    """Parser for SSH authentication logs."""
    
    # Standard syslog SSH format
    # Example: "Aug 12 15:03:00 firewall sshd[1234]: Failed password for user admin from 192.168.1.50 port 45234 ssh2"
    # Example: "Aug 12 15:03:00 firewall sshd[1234]: Invalid user testuser from 192.168.1.50 port 45234"
    # Example: "Aug 12 15:03:00 firewall sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 45234 ssh2"
    SYSLOG_SSH_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
        r'\S+\s+'  # Hostname
        r'sshd\[\d+\]:\s+'  # Process name and PID
        r'(?P<message>.*)'  # Full message
    )
    
    # Detailed SSH event patterns
    # Failed password attempt
    FAILED_PASSWORD_PATTERN = re.compile(
        r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+) port (?P<port>\d+)'
    )
    
    # Invalid user attempt
    INVALID_USER_PATTERN = re.compile(
        r'Invalid user (?P<user>\S+) from (?P<ip>[\d\.]+) port (?P<port>\d+)'
    )
    
    # Accepted authentication
    ACCEPTED_PATTERN = re.compile(
        r'Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d\.]+) port (?P<port>\d+)'
    )
    
    # Connection opened
    CONNECTION_PATTERN = re.compile(
        r'Connection closed by (?:authenticating )?user (?P<user>\S+) (?P<ip>[\d\.]+) port (?P<port>\d+)'
    )
    
    # Received disconnect message
    DISCONNECT_PATTERN = re.compile(
        r'Received disconnect from (?P<ip>[\d\.]+) port (?P<port>\d+):\s*(?P<code>\d+):\s*(?P<reason>.*?)(?:\s+\[preauth\])?$'
    )
    
    # Authentication refused
    AUTH_REFUSED_PATTERN = re.compile(
        r'Authentication refused:? (?P<reason>.*?) from (?P<ip>[\d\.]+) port (?P<port>\d+)'
    )
    
    # Connection attempt from different IP formats
    CONNECTION_ATTEMPT_PATTERN = re.compile(
        r'(?:Invalid user|Connection from|Attempt from) (?P<info>\S+) (?P<ip>[\d\.]+)'
    )
    
    def __init__(self):
        """Initialize the SSH log parser."""
        self.event_counter = 0
        self.current_year = datetime.now().year
    
    def parse_line(self, line: str, log_type: str = 'auto') -> Optional[Dict]:
        """
        Parse a single SSH log line.
        
        Args:
            line: A single log line
            log_type: 'syslog' or 'auto' for automatic detection
            
        Returns:
            A normalized log dictionary or None if parsing fails
        """
        if not line.strip():
            return None
        
        match = self.SYSLOG_SSH_PATTERN.search(line)
        if not match:
            return None
        
        timestamp_str = match.group('timestamp')
        message = match.group('message')
        
        # Parse timestamp
        timestamp = self._parse_syslog_timestamp(timestamp_str)
        if not timestamp:
            return None
        
        # Parse the SSH event message
        return self._parse_ssh_event(timestamp, message)
    
    def _parse_ssh_event(self, timestamp: str, message: str) -> Optional[Dict]:
        """
        Parse the SSH event message to extract details.
        
        Args:
            timestamp: Already parsed timestamp
            message: SSH syslog message
            
        Returns:
            Normalized log dictionary or None
        """
        self.event_counter += 1
        
        # Try to parse failed password attempt
        match = self.FAILED_PASSWORD_PATTERN.search(message)
        if match:
            return {
                'timestamp': timestamp,
                'source': 'ssh',
                'event_type': 'Failed login',
                'ip': match.group('ip'),
                'status': 'failed',
                'message': f"Failed password for user {match.group('user')} from {match.group('ip')} port {match.group('port')}",
                'username': match.group('user'),
                'event_id': self.event_counter
            }
        
        # Try to parse invalid user attempt
        match = self.INVALID_USER_PATTERN.search(message)
        if match:
            return {
                'timestamp': timestamp,
                'source': 'ssh',
                'event_type': 'Invalid user',
                'ip': match.group('ip'),
                'status': 'invalid_user',
                'message': f"Invalid user {match.group('user')} from {match.group('ip')} port {match.group('port')}",
                'username': match.group('user'),
                'event_id': self.event_counter
            }
        
        # Try to parse accepted authentication
        match = self.ACCEPTED_PATTERN.search(message)
        if match:
            return {
                'timestamp': timestamp,
                'source': 'ssh',
                'event_type': 'Successful login',
                'ip': match.group('ip'),
                'status': 'success',
                'message': f"Accepted {match.group('method')} for user {match.group('user')} from {match.group('ip')} port {match.group('port')}",
                'username': match.group('user'),
                'event_id': self.event_counter
            }
        
        # Try to parse disconnect
        match = self.DISCONNECT_PATTERN.search(message)
        if match:
            return {
                'timestamp': timestamp,
                'source': 'ssh',
                'event_type': 'Disconnect',
                'ip': match.group('ip'),
                'status': 'disconnect',
                'message': f"Disconnect from {match.group('ip')} port {match.group('port')}: {match.group('reason')}",
                'username': '',
                'event_id': self.event_counter
            }
        
        # Try to parse authentication refused
        match = self.AUTH_REFUSED_PATTERN.search(message)
        if match:
            return {
                'timestamp': timestamp,
                'source': 'ssh',
                'event_type': 'Authentication refused',
                'ip': match.group('ip'),
                'status': 'refused',
                'message': f"Authentication refused: {match.group('reason')} from {match.group('ip')} port {match.group('port')}",
                'username': '',
                'event_id': self.event_counter
            }
        
        # Try to parse connection attempt
        match = self.CONNECTION_ATTEMPT_PATTERN.search(message)
        if match:
            ip = match.group('ip')
            info = match.group('info')
            return {
                'timestamp': timestamp,
                'source': 'ssh',
                'event_type': 'Connection attempt',
                'ip': ip,
                'status': 'attempt',
                'message': message,
                'username': info if info != ip else '',
                'event_id': self.event_counter
            }
        
        # Generic SSH event if no specific pattern matches
        # Try to extract IP from message
        ip_match = re.search(r'from ([\d\.]+)', message)
        ip = ip_match.group(1) if ip_match else ''
        
        # Try to extract username
        user_match = re.search(r'(?:for|user)\s+(\S+)', message)
        username = user_match.group(1) if user_match else ''
        
        return {
            'timestamp': timestamp,
            'source': 'ssh',
            'event_type': 'SSH event',
            'ip': ip,
            'status': 'unknown',
            'message': message,
            'username': username,
            'event_id': self.event_counter
        }
    
    def _parse_syslog_timestamp(self, timestamp_str: str) -> Optional[str]:
        """
        Parse syslog timestamp to standard format.
        
        Converts: "Aug 12 15:03:00"
        To:       "2026-08-12 15:03:00"
        
        Args:
            timestamp_str: Timestamp from syslog
            
        Returns:
            Normalized timestamp string or None if parsing fails
        """
        try:
            # Parse without year (syslog doesn't include year)
            dt = datetime.strptime(timestamp_str.strip(), '%b %d %H:%M:%S')
            
            # Add current year
            dt = dt.replace(year=self.current_year)
            
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            return None
    
    def parse_file(self, filepath: str) -> List[Dict]:
        """
        Parse an entire SSH log file.
        
        Args:
            filepath: Path to the log file (typically /var/log/auth.log or /var/log/secure)
            
        Returns:
            List of normalized log dictionaries
        """
        logs = []
        self.event_counter = 0
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed = self.parse_line(line)
                    if parsed:
                        logs.append(parsed)
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
        except Exception as e:
            print(f"Error reading file '{filepath}': {e}")
        
        return logs


def parse_ssh_logs(filepath: str) -> List[Dict]:
    """
    Parse SSH logs from a file.
    
    Args:
        filepath: Path to SSH log file (typically /var/log/auth.log or /var/log/secure)
        
    Returns:
        List of normalized log dictionaries
    """
    parser = SSHLogParser()
    return parser.parse_file(filepath)


if __name__ == '__main__':
    # Example usage
    import json
    
    # Example SSH log lines
    failed_password_line = 'Aug 12 15:03:00 firewall sshd[1234]: Failed password for admin from 192.168.1.50 port 45234 ssh2'
    invalid_user_line = 'Aug 12 15:03:00 firewall sshd[1234]: Invalid user testuser from 192.168.1.50 port 45234'
    accepted_line = 'Aug 12 15:03:00 firewall sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 45234 ssh2'
    disconnect_line = 'Aug 12 15:03:00 firewall sshd[1234]: Received disconnect from 192.168.1.50 port 45234: 11: disconnected by user [preauth]'
    
    parser = SSHLogParser()
    
    print("Failed Password Attempt:")
    parsed = parser.parse_line(failed_password_line)
    print(json.dumps(parsed, indent=2))
    
    print("\nInvalid User Attempt:")
    parsed = parser.parse_line(invalid_user_line)
    print(json.dumps(parsed, indent=2))
    
    print("\nSuccessful Login:")
    parsed = parser.parse_line(accepted_line)
    print(json.dumps(parsed, indent=2))
    
    print("\nDisconnect Event:")
    parsed = parser.parse_line(disconnect_line)
    print(json.dumps(parsed, indent=2))