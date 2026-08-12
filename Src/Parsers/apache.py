"""
Apache Log Parser

Parses Apache access and error logs into a normalized log format.
Supports both combined and common log formats.

Normalized log structure:
{
    'timestamp': str,       # YYYY-MM-DD HH:MM:SS
    'source': str,          # 'apache'
    'event_type': str,      # 'HTTP request', 'HTTP error', etc.
    'ip': str,              # Client IP address
    'status': str,          # HTTP status code or 'error'
    'message': str,         # Log details
    'username': str,        # Authenticated user (if applicable)
    'event_id': int         # Unique identifier
}
"""

import re
from datetime import datetime
from typing import Dict, List, Optional


class ApacheLogParser:
    """Parser for Apache access and error logs."""
    
    # Apache Combined Log Format: IP IDENT USERID [TIMESTAMP] "REQUEST" STATUS BYTES REFERRER USERAGENT
    # Apache Common Log Format: IP IDENT USERID [TIMESTAMP] "REQUEST" STATUS BYTES
    COMMON_LOG_PATTERN = re.compile(
        r'(?P<ip>[\d\.]+|\S+) '  # IP address or hostname
        r'(?P<ident>\S+) '        # IDENT (usually -)
        r'(?P<user>\S+) '         # User (usually -)
        r'\[(?P<timestamp>[^\]]+)\] '  # Timestamp
        r'"(?P<method>\S+) '      # HTTP Method
        r'(?P<path>\S+) '         # Request path
        r'(?P<protocol>\S+)" '    # HTTP Protocol
        r'(?P<status>\d{3}|\S+) ' # HTTP Status code
        r'(?P<bytes>[\d-]+)'      # Bytes sent
        r'(?:\s+"(?P<referrer>[^"]*)"|$)'  # Referrer (optional)
        r'(?:\s+"(?P<useragent>[^"]*)"|$)' # User Agent (optional)
    )
    
    # Apache Error Log Pattern: [TIMESTAMP] [MODULE:LEVEL] [PID THREADID] [CLIENT IP] MESSAGE
    ERROR_LOG_PATTERN = re.compile(
        r'\[(?P<timestamp>[^\]]+)\] '  # Timestamp
        r'\[(?P<module>[^\]:]+)(?::(?P<level>\w+))?\] '  # Module and level
        r'(?:\[pid (?P<pid>\d+)(?::tid (?P<tid>\d+))?\] )?'  # PID/TID (optional)
        r'(?:\[client (?P<client_ip>[^\]]+)\] )?'  # Client IP (optional)
        r'(?P<message>.*)'  # Error message
    )
    
    def __init__(self):
        """Initialize the Apache log parser."""
        self.event_counter = 0
    
    def parse_line(self, line: str, log_type: str = 'access') -> Optional[Dict]:
        """
        Parse a single Apache log line.
        
        Args:
            line: A single log line
            log_type: 'access' for access logs, 'error' for error logs
            
        Returns:
            A normalized log dictionary or None if parsing fails
        """
        if not line.strip():
            return None
        
        if log_type == 'error':
            return self._parse_error_log(line)
        else:
            return self._parse_access_log(line)
    
    def _parse_access_log(self, line: str) -> Optional[Dict]:
        """Parse Apache access log line (common or combined format)."""
        match = self.COMMON_LOG_PATTERN.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        self.event_counter += 1
        
        # Parse timestamp from Apache format: [12/Aug/2026:15:03:00 +0000]
        timestamp = self._parse_apache_timestamp(data['timestamp'])
        if not timestamp:
            return None
        
        # Determine event type based on HTTP method and status
        status_code = data['status']
        method = data['method']
        event_type = f'{method} request'
        
        # Build message with request details
        message = f'{method} {data["path"]} {data["protocol"]}'
        if data.get('referrer') and data['referrer'] != '-':
            message += f' | Referrer: {data["referrer"]}'
        if data.get('useragent') and data['useragent'] != '-':
            message += f' | User-Agent: {data["useragent"]}'
        
        # Determine username
        username = data['user'] if data['user'] != '-' else ''
        
        return {
            'timestamp': timestamp,
            'source': 'apache',
            'event_type': event_type,
            'ip': data['ip'],
            'status': status_code,
            'message': message,
            'username': username,
            'event_id': self.event_counter
        }
    
    def _parse_error_log(self, line: str) -> Optional[Dict]:
        """Parse Apache error log line."""
        match = self.ERROR_LOG_PATTERN.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        self.event_counter += 1
        
        # Parse timestamp
        timestamp = self._parse_apache_timestamp(data['timestamp'])
        if not timestamp:
            return None
        
        level = data.get('level', 'error').lower()
        module = data.get('module', 'apache')
        
        return {
            'timestamp': timestamp,
            'source': 'apache',
            'event_type': f'HTTP {level}',
            'ip': data.get('client_ip', ''),
            'status': level.upper(),
            'message': f'[{module}] {data["message"]}',
            'username': '',
            'event_id': self.event_counter
        }
    
    def _parse_apache_timestamp(self, timestamp_str: str) -> Optional[str]:
        """
        Parse Apache timestamp format to standard format.
        
        Converts: 12/Aug/2026:15:03:00 +0000 or Wed Aug 12 15:03:00 2026
        To:       2026-08-12 15:03:00
        
        Args:
            timestamp_str: Timestamp from Apache log
            
        Returns:
            Normalized timestamp string or None if parsing fails
        """
        # Try error log format first: Wed Aug 12 15:03:00 2026
        try:
            dt = datetime.strptime(timestamp_str, '%a %b %d %H:%M:%S %Y')
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
        
        # Try common log format: 12/Aug/2026:15:03:00 +0000
        try:
            # Remove timezone info if present
            timestamp_str = timestamp_str.split(' ')[0]
            dt = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, IndexError):
            return None
    
    def parse_file(self, filepath: str, log_type: str = 'access') -> List[Dict]:
        """
        Parse an entire Apache log file.
        
        Args:
            filepath: Path to the log file
            log_type: 'access' or 'error'
            
        Returns:
            List of normalized log dictionaries
        """
        logs = []
        self.event_counter = 0
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed = self.parse_line(line, log_type)
                    if parsed:
                        logs.append(parsed)
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
        except Exception as e:
            print(f"Error reading file '{filepath}': {e}")
        
        return logs


def parse_apache_access_logs(filepath: str) -> List[Dict]:
    """
    Parse Apache access logs from a file.
    
    Args:
        filepath: Path to Apache access log file
        
    Returns:
        List of normalized log dictionaries
    """
    parser = ApacheLogParser()
    return parser.parse_file(filepath, log_type='access')


def parse_apache_error_logs(filepath: str) -> List[Dict]:
    """
    Parse Apache error logs from a file.
    
    Args:
        filepath: Path to Apache error log file
        
    Returns:
        List of normalized log dictionaries
    """
    parser = ApacheLogParser()
    return parser.parse_file(filepath, log_type='error')


if __name__ == '__main__':
    # Example usage
    import json
    
    # Example Apache access log line
    access_log_line = '192.168.1.50 - admin [12/Aug/2026:15:03:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    
    # Example Apache error log line
    error_log_line = '[Wed Aug 12 15:03:00 2026] [core:warn] [pid 1234:tid 5678] [client 192.168.1.100] File not found'
    
    parser = ApacheLogParser()
    
    print("Access Log Parse:")
    access_parsed = parser.parse_line(access_log_line, 'access')
    print(json.dumps(access_parsed, indent=2))
    
    print("\nError Log Parse:")
    error_parsed = parser.parse_line(error_log_line, 'error')
    print(json.dumps(error_parsed, indent=2))