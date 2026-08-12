"""
Firewall Log Parser

Parses firewall logs (iptables, pfSense, Cisco ASA, etc.) into a normalized log format.
Supports multiple firewall log formats commonly found in Linux and network devices.

Normalized log structure:
{
    'timestamp': str,       # YYYY-MM-DD HH:MM:SS
    'source': str,          # 'firewall'
    'event_type': str,      # 'DENY', 'ALLOW', 'DROP', etc.
    'ip': str,              # Source IP address
    'status': str,          # 'DENY', 'ALLOW', 'DROP', 'REJECT', etc.
    'message': str,         # Log details (ports, protocols, etc.)
    'username': str,        # Empty for firewall logs
    'event_id': int         # Unique identifier
}
"""

import re
from datetime import datetime
from typing import Dict, List, Optional


class FirewallLogParser:
    """Parser for firewall logs from various sources."""
    
    # iptables log format: "Kernel log format"
    # Example: "Jan 12 15:03:00 hostname kernel: REJECT IN=eth0 OUT= MAC=... SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP SPT=45234 DPT=22 WINDOW=65535"
    IPTABLES_PATTERN = re.compile(
        r'(?P<timestamp>.*?)\s+\S+\s+kernel:\s+'  # Timestamp and kernel prefix
        r'(?P<action>\w+)\s+'  # Action (REJECT, ACCEPT, DROP, etc.)
        r'(?:IN=(?P<in_interface>\S+)\s+)?'  # Incoming interface (optional)
        r'(?:OUT=(?P<out_interface>\S+)\s+)?'  # Outgoing interface (optional)
        r'(?:MAC=\S+\s+)?'  # MAC address (skip)
        r'(?:SRC=(?P<src_ip>[\d\.]+)\s+)?'  # Source IP (optional)
        r'(?:DST=(?P<dst_ip>[\d\.]+)\s+)?'  # Destination IP (optional)
        r'(?:PROTO=(?P<protocol>\w+)\s+)?'  # Protocol (optional)
        r'(?:SPT=(?P<src_port>\d+)\s+)?'  # Source port (optional)
        r'(?:DPT=(?P<dst_port>\d+)\s+)?'  # Destination port (optional)
        r'(?P<rest>.*)'  # Remaining fields
    )
    
    # pfSense/BSD log format
    # Example: "Aug 12 15:03:00 firewall.local filterlog: 0,,,0,em0,match,in,4,0x0,,255,60374,0,DF,TCP,40,40,54321,192.168.1.50,443,10.0.0.1,S,2883584478,,1460,mss,ts;nop;nop;sackOK|,,,0x00,,"
    # Using a simple pattern to extract the start
    PFSENSE_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+filterlog:\s*'
        r'(?P<data>.*)'  # Capture all comma-separated data
    )
    
    # Standard syslog format (used by many firewalls)
    # Example: "Aug 12 15:03:00 firewall DENY: IN=eth0 OUT=eth1 SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP DPT=22"
    SYSLOG_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
        r'\S+\s+'  # Hostname
        r'(?P<event_type>[^:]+):\s+'  # Event type
        r'(?P<message>.*)'  # Message
    )
    
    def __init__(self):
        """Initialize the firewall log parser."""
        self.event_counter = 0
        self.current_year = datetime.now().year
    
    def parse_line(self, line: str, log_type: str = 'auto') -> Optional[Dict]:
        """
        Parse a single firewall log line.
        
        Args:
            line: A single log line
            log_type: 'iptables', 'pfsense', 'syslog', or 'auto' for automatic detection
            
        Returns:
            A normalized log dictionary or None if parsing fails
        """
        if not line.strip():
            return None
        
        if log_type == 'auto':
            # Try to auto-detect log format
            if 'filterlog' in line:
                return self._parse_pfsense_log(line)
            elif 'kernel:' in line:
                return self._parse_iptables_log(line)
            else:
                return self._parse_syslog_log(line)
        elif log_type == 'iptables':
            return self._parse_iptables_log(line)
        elif log_type == 'pfsense':
            return self._parse_pfsense_log(line)
        else:
            return self._parse_syslog_log(line)
    
    def _parse_iptables_log(self, line: str) -> Optional[Dict]:
        """Parse iptables kernel log line."""
        match = self.IPTABLES_PATTERN.search(line)
        if not match:
            return None
        
        data = match.groupdict()
        self.event_counter += 1
        
        # Parse timestamp
        timestamp = self._parse_syslog_timestamp(data['timestamp'])
        if not timestamp:
            return None
        
        # Get source IP (primary identifier for firewall logs)
        src_ip = data.get('src_ip', '')
        
        # Build message with protocol and port information
        message_parts = []
        if data.get('in_interface'):
            message_parts.append(f"IN={data['in_interface']}")
        if data.get('out_interface'):
            message_parts.append(f"OUT={data['out_interface']}")
        if data.get('protocol'):
            message_parts.append(f"PROTO={data['protocol']}")
        if data.get('src_port'):
            message_parts.append(f"SPT={data['src_port']}")
        if data.get('dst_port'):
            message_parts.append(f"DPT={data['dst_port']}")
        if data.get('dst_ip'):
            message_parts.append(f"DST={data['dst_ip']}")
        
        message = ' '.join(message_parts)
        
        return {
            'timestamp': timestamp,
            'source': 'firewall',
            'event_type': f"FIREWALL {data['action']}",
            'ip': src_ip,
            'status': data['action'],
            'message': message,
            'username': '',
            'event_id': self.event_counter
        }
    
    def _parse_pfsense_log(self, line: str) -> Optional[Dict]:
        """Parse pfSense filterlog format using field-based approach."""
        match = self.PFSENSE_PATTERN.search(line)
        if not match:
            return None
        
        timestamp_str = match.group('timestamp')
        data_str = match.group('data')
        
        # Parse timestamp
        timestamp = self._parse_syslog_timestamp(timestamp_str)
        if not timestamp:
            return None
        
        # Split by comma and extract fields
        fields = data_str.split(',')
        if len(fields) < 23:  # Need at least 23 fields
            return None
        
        self.event_counter += 1
        
        try:
            # Field mapping based on pfSense filterlog format
            # Fields 0-6: rule_num, subrule, anchorchain, anchorid, interface, reason, direction
            # Fields 7-18: action, protocol, version, tos, ttl, id, offset, flags, protocolnum, length, src_port, dst_port
            # Fields 19+: src_ip, dst_port (again), dst_ip, tcp_flags, seq, ack, window, urg, options...
            
            action = fields[7].strip().upper() if len(fields) > 7 else 'UNKNOWN'
            protocol = fields[8].strip().lower() if len(fields) > 8 else ''
            direction = fields[6].strip() if len(fields) > 6 else ''
            interface = fields[4].strip() if len(fields) > 4 else ''
            
            # IP addresses are typically after field 19
            src_ip = fields[20].strip() if len(fields) > 20 else ''
            dst_ip = fields[22].strip() if len(fields) > 22 else ''
            src_port = fields[19].strip() if len(fields) > 19 else ''
            dst_port = fields[21].strip() if len(fields) > 21 else ''
            
            # Build message with connection details
            message_parts = []
            if interface:
                message_parts.append(f"Interface={interface}")
            if direction:
                message_parts.append(f"Direction={direction}")
            if protocol:
                message_parts.append(f"Protocol={protocol}")
            if src_port:
                message_parts.append(f"SrcPort={src_port}")
            if dst_port:
                message_parts.append(f"DstPort={dst_port}")
            if dst_ip:
                message_parts.append(f"DstIP={dst_ip}")
            
            message = ' | '.join(message_parts)
            
            return {
                'timestamp': timestamp,
                'source': 'firewall',
                'event_type': f"FIREWALL {action}",
                'ip': src_ip,
                'status': action,
                'message': message,
                'username': '',
                'event_id': self.event_counter
            }
        except (IndexError, ValueError):
            return None
    
    def _parse_syslog_log(self, line: str) -> Optional[Dict]:
        """Parse generic syslog firewall format."""
        match = self.SYSLOG_PATTERN.search(line)
        if not match:
            return None
        
        data = match.groupdict()
        self.event_counter += 1
        
        # Parse timestamp
        timestamp = self._parse_syslog_timestamp(data['timestamp'])
        if not timestamp:
            return None
        
        message = data.get('message', '')
        
        # Try to extract IP from message
        ip_match = re.search(r'SRC=(?P<src_ip>[\d\.]+)', message)
        src_ip = ip_match.group('src_ip') if ip_match else ''
        
        # Determine status from event type
        event_type_upper = data['event_type'].upper()
        
        return {
            'timestamp': timestamp,
            'source': 'firewall',
            'event_type': f"FIREWALL {event_type_upper}",
            'ip': src_ip,
            'status': event_type_upper,
            'message': message,
            'username': '',
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
    
    def parse_file(self, filepath: str, log_type: str = 'auto') -> List[Dict]:
        """
        Parse an entire firewall log file.
        
        Args:
            filepath: Path to the log file
            log_type: 'iptables', 'pfsense', 'syslog', or 'auto'
            
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


def parse_firewall_logs(filepath: str, log_type: str = 'auto') -> List[Dict]:
    """
    Parse firewall logs from a file.
    
    Args:
        filepath: Path to firewall log file
        log_type: 'iptables', 'pfsense', 'syslog', or 'auto' for auto-detection
        
    Returns:
        List of normalized log dictionaries
    """
    parser = FirewallLogParser()
    return parser.parse_file(filepath, log_type)


if __name__ == '__main__':
    # Example usage
    import json
    
    # Example iptables log line
    iptables_line = 'Aug 12 15:03:00 firewall kernel: DENY IN=eth0 OUT=eth1 SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP SPT=45234 DPT=22'
    
    # Example pfSense log line
    pfsense_line = 'Aug 12 15:03:00 firewall filterlog: 0,,,0,em0,match,in,allow,tcp,4,0x0,,255,60374,0,DF,TCP,40,40,54321,192.168.1.50,443,10.0.0.1,S,2883584478,,1460,mss,ts;nop;nop;sackOK|,,,0x00,,'
    
    # Example generic syslog line
    syslog_line = 'Aug 12 15:03:00 firewall DENY: IN=eth0 OUT=eth1 SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP DPT=22'
    
    parser = FirewallLogParser()
    
    print("iptables Log Parse:")
    iptables_parsed = parser.parse_line(iptables_line, 'iptables')
    print(json.dumps(iptables_parsed, indent=2))
    
    print("\npfSense Log Parse:")
    pfsense_parsed = parser.parse_line(pfsense_line, 'pfsense')
    print(json.dumps(pfsense_parsed, indent=2))
    
    print("\nSyslog Format Parse:")
    syslog_parsed = parser.parse_line(syslog_line, 'syslog')
    print(json.dumps(syslog_parsed, indent=2))