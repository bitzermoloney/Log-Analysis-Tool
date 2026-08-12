"""
Windows Event Log Parser

Parses Windows event logs (Security, Application, System) into a normalized log format.
Supports multiple Windows log formats including Event Viewer exports and log files.

Normalized log structure:
{
    'timestamp': str,       # YYYY-MM-DD HH:MM:SS
    'source': str,          # 'windows'
    'event_type': str,      # Event classification (e.g., 'Failed logon', 'Process creation')
    'ip': str,              # Source IP address (if applicable)
    'status': str,          # Event status/result
    'message': str,         # Log details
    'username': str,        # Username involved in event
    'event_id': int         # Unique identifier
}

Common Windows Event IDs:
- 4624: Successful account logon
- 4625: Failed account logon
- 4634: Account logoff
- 4648: Logon using explicit credentials
- 4672: Special privileges assigned to new logon
- 4688: Process creation
- 5140: Network share access
"""

import re
import csv
from io import StringIO
from datetime import datetime
from typing import Dict, List, Optional


class WindowsLogParser:
    """Parser for Windows event logs."""
    
    # Common Windows timestamp format
    # Example: "2026-08-12T15:03:00" or "8/12/2026 15:03:00"
    
    # Windows event log CSV format (common export from Event Viewer)
    # Expected columns: Type,Date,Time,Source,ID,Task Category,Level,User,Computer,Description
    
    # Common Windows event patterns for text format
    # Example: "EventID: 4625, User: DOMAIN\admin, Source IP: 192.168.1.50, Result: Failure"
    
    # Event ID patterns
    EVENT_ID_PATTERNS = {
        '4624': ('Successful logon', 'success'),
        '4625': ('Failed logon', 'failed'),
        '4634': ('Account logoff', 'logoff'),
        '4648': ('Logon with explicit credentials', 'explicit_logon'),
        '4672': ('Special privileges assigned', 'privilege_change'),
        '4688': ('Process creation', 'process_creation'),
        '4689': ('Process terminated', 'process_termination'),
        '4720': ('User account created', 'account_created'),
        '4722': ('User account enabled', 'account_enabled'),
        '4723': ('Password change attempt', 'password_change'),
        '4725': ('User account disabled', 'account_disabled'),
        '4726': ('User account deleted', 'account_deleted'),
        '4740': ('Account locked out', 'account_locked'),
        '4781': ('Account renamed', 'account_renamed'),
        '5140': ('Network share accessed', 'share_access'),
        '5156': ('Network connection allowed', 'connection_allowed'),
        '5157': ('Network connection blocked', 'connection_blocked'),
    }
    
    # Text log line pattern (flexible format)
    TEXT_LOG_PATTERN = re.compile(
        r'(?:\[?(?P<timestamp>[\d\-\s:/]+)\]?)?\s*'  # Optional timestamp
        r'(?:EventID:\s*(?P<event_id>\d+))?\s*'  # Optional event ID
        r'(?:Level:\s*(?P<level>\w+))?\s*'  # Optional level
        r'(?:User:\s*(?P<user>[^\,]+))?\s*'  # Optional user
        r'(?:Computer:\s*(?P<computer>\S+))?\s*'  # Optional computer
        r'(?:Source\s*IP:\s*(?P<src_ip>[\d\.]+))?\s*'  # Optional source IP
        r'(?P<message>.*)'  # Message
    )
    
    def __init__(self):
        """Initialize the Windows log parser."""
        self.event_counter = 0
        self.current_year = datetime.now().year
    
    def parse_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single Windows log line.
        
        Args:
            line: A single log line
            
        Returns:
            A normalized log dictionary or None if parsing fails
        """
        if not line.strip():
            return None
        
        # Try text format first
        return self._parse_text_log(line)
    
    def parse_csv_line(self, row: Dict) -> Optional[Dict]:
        """
        Parse a CSV row from Windows Event Viewer export.
        
        Args:
            row: A dictionary representing a CSV row
            
        Returns:
            A normalized log dictionary or None if parsing fails
        """
        if not row or not any(row.values()):
            return None
        
        self.event_counter += 1
        
        # Extract fields (column names may vary)
        timestamp_str = row.get('Date') or row.get('Time') or ''
        event_id = row.get('ID') or row.get('EventID') or ''
        level = row.get('Level') or row.get('Type') or ''
        user = row.get('User') or ''
        computer = row.get('Computer') or ''
        description = row.get('Description') or ''
        
        # Parse timestamp
        timestamp = self._parse_windows_timestamp(timestamp_str)
        if not timestamp:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Get event type from event ID
        event_type = 'Windows event'
        status = level.lower() if level else 'info'
        
        if event_id in self.EVENT_ID_PATTERNS:
            event_type, status = self.EVENT_ID_PATTERNS[event_id]
        
        # Extract IP from description if present
        ip_match = re.search(r'(?:Source IP|IP Address):\s*([\d\.]+)', description)
        src_ip = ip_match.group(1) if ip_match else ''
        
        return {
            'timestamp': timestamp,
            'source': 'windows',
            'event_type': event_type,
            'ip': src_ip,
            'status': status,
            'message': description,
            'username': user,
            'event_id': self.event_counter
        }
    
    def _parse_text_log(self, line: str) -> Optional[Dict]:
        """Parse Windows event log in text format."""
        self.event_counter += 1
        
        # Extract timestamp if present (look for ISO or US date format with optional time)
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2})\s+(\d{1,2}:\d{2}:\d{2})', line)
        timestamp = None
        
        if timestamp_match:
            full_timestamp = f"{timestamp_match.group(1)} {timestamp_match.group(2)}"
            timestamp = self._parse_windows_timestamp(full_timestamp)
        else:
            # Try other date formats with time
            timestamp_match = re.search(r'(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2}:\d{2})', line)
            if timestamp_match:
                full_timestamp = f"{timestamp_match.group(1)} {timestamp_match.group(2)}"
                timestamp = self._parse_windows_timestamp(full_timestamp)
        
        if not timestamp:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Extract EventID
        event_id_match = re.search(r'EventID:\s*(\d+)', line)
        event_id = event_id_match.group(1) if event_id_match else ''
        
        # Extract Level
        level_match = re.search(r'Level:\s*(\w+)', line)
        level = level_match.group(1) if level_match else ''
        
        # Extract User
        user_match = re.search(r'User:\s*([^\,]+?)(?:\s*,|$)', line)
        user = user_match.group(1).strip() if user_match else ''
        
        # Extract Source IP
        ip_match = re.search(r'(?:Source\s*IP|IP\s*Address):\s*([\d\.]+)', line)
        src_ip = ip_match.group(1) if ip_match else ''
        
        # Determine event type and status
        event_type = 'Windows event'
        status = 'info'
        
        if event_id and event_id in self.EVENT_ID_PATTERNS:
            event_type, status = self.EVENT_ID_PATTERNS[event_id]
        else:
            # Try to infer from level
            level_lower = level.lower()
            if 'error' in level_lower:
                status = 'error'
            elif 'warning' in level_lower:
                status = 'warning'
            elif 'success' in level_lower or 'information' in level_lower:
                status = 'success'
        
        # Use the full line as message
        message = line
        
        return {
            'timestamp': timestamp,
            'source': 'windows',
            'event_type': event_type,
            'ip': src_ip,
            'status': status,
            'message': message,
            'username': user,
            'event_id': self.event_counter
        }
    
    def _parse_windows_timestamp(self, timestamp_str: str) -> Optional[str]:
        """
        Parse Windows timestamp formats to standard format.
        
        Supports:
        - ISO format: "2026-08-12T15:03:00"
        - ISO format with space: "2026-08-12 15:03:00"
        - US format: "8/12/2026 15:03:00"
        - US format: "8/12/2026"
        - Various other Windows Event Viewer formats
        
        Returns:
            Normalized timestamp string or None if parsing fails
        """
        if not timestamp_str or not timestamp_str.strip():
            return None
        
        timestamp_str = timestamp_str.strip()
        
        # Try ISO format with space: 2026-08-12 15:03:00
        try:
            dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
        
        # Try ISO format with T: 2026-08-12T15:03:00
        try:
            if 'T' in timestamp_str:
                dt = datetime.fromisoformat(timestamp_str.split('.')[0])  # Remove milliseconds
                return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, IndexError):
            pass
        
        # Try US date format: 8/12/2026 15:03:00
        try:
            dt = datetime.strptime(timestamp_str, '%m/%d/%Y %H:%M:%S')
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
        
        # Try US date format without time: 8/12/2026
        try:
            dt = datetime.strptime(timestamp_str, '%m/%d/%Y')
            return dt.strftime('%Y-%m-%d 00:00:00')
        except ValueError:
            pass
        
        # Try European format: 12/8/2026 15:03:00
        try:
            dt = datetime.strptime(timestamp_str, '%d/%m/%Y %H:%M:%S')
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
        
        # Try ISO date only: 2026-08-12
        try:
            dt = datetime.strptime(timestamp_str, '%Y-%m-%d')
            return dt.strftime('%Y-%m-%d 00:00:00')
        except ValueError:
            pass
        
        return None
    
    def parse_file(self, filepath: str, file_format: str = 'auto') -> List[Dict]:
        """
        Parse an entire Windows log file.
        
        Args:
            filepath: Path to the log file
            file_format: 'csv', 'text', or 'auto' for automatic detection
            
        Returns:
            List of normalized log dictionaries
        """
        logs = []
        self.event_counter = 0
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                # Determine format if auto
                if file_format == 'auto':
                    first_line = f.readline()
                    f.seek(0)
                    
                    if first_line.startswith(('Type', 'Event', 'Date')) or ',' in first_line:
                        file_format = 'csv'
                    else:
                        file_format = 'text'
                
                if file_format == 'csv':
                    # Parse as CSV
                    reader = csv.DictReader(f)
                    if reader:
                        for row in reader:
                            parsed = self.parse_csv_line(row)
                            if parsed:
                                logs.append(parsed)
                else:
                    # Parse as text
                    for line in f:
                        parsed = self.parse_line(line)
                        if parsed:
                            logs.append(parsed)
        
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
        except Exception as e:
            print(f"Error reading file '{filepath}': {e}")
        
        return logs


def parse_windows_logs(filepath: str, file_format: str = 'auto') -> List[Dict]:
    """
    Parse Windows logs from a file.
    
    Args:
        filepath: Path to Windows log file
        file_format: 'csv', 'text', or 'auto' for auto-detection
        
    Returns:
        List of normalized log dictionaries
    """
    parser = WindowsLogParser()
    return parser.parse_file(filepath, file_format)


if __name__ == '__main__':
    # Example usage
    import json
    
    # Example Windows event log lines with proper timestamps
    failed_logon_line = '2026-08-12 15:03:00 EventID: 4625, Level: Error, User: DOMAIN\\testuser, Computer: WORKSTATION01, Source IP: 192.168.1.50, An account failed to log on'
    successful_logon_line = '2026-08-12 15:03:01 EventID: 4624, Level: Information, User: DOMAIN\\admin, Computer: WORKSTATION01, An account was successfully logged on'
    process_creation_line = '2026-08-12 15:03:02 EventID: 4688, Level: Information, User: DOMAIN\\admin, Computer: WORKSTATION01, A new process has been created. Process Name: C:\\Windows\\System32\\notepad.exe'
    share_access_line = '2026-08-12 15:03:03 EventID: 5140, Level: Information, User: DOMAIN\\admin, Computer: SERVER01, Source IP: 192.168.1.100, Network share was accessed'
    
    parser = WindowsLogParser()
    
    print("Failed Logon Event:")
    parsed = parser.parse_line(failed_logon_line)
    print(json.dumps(parsed, indent=2))
    
    print("\nSuccessful Logon Event:")
    parsed = parser.parse_line(successful_logon_line)
    print(json.dumps(parsed, indent=2))
    
    print("\nProcess Creation Event:")
    parsed = parser.parse_line(process_creation_line)
    print(json.dumps(parsed, indent=2))
    
    print("\nNetwork Share Access Event:")
    parsed = parser.parse_line(share_access_line)
    print(json.dumps(parsed, indent=2))
    
    # Example CSV parsing
    print("\n\nCSV Format Example:")
    csv_row = {
        'Type': 'Error',
        'Date': '8/12/2026',
        'Time': '15:03:00',
        'Source': 'Security',
        'ID': '4625',
        'Task Category': 'Logon',
        'Level': 'Error',
        'User': 'DOMAIN\\admin',
        'Computer': 'WORKSTATION01',
        'Description': 'An account failed to log on. Source IP: 192.168.1.50'
    }
    parsed = parser.parse_csv_line(csv_row)
    print(json.dumps(parsed, indent=2))