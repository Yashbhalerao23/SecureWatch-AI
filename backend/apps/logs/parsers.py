"""
AI Log Monitoring & Security Detection Platform
Logs App - Windows Sysmon Log Parser

This module provides parsing functionality for Windows Sysmon (System Monitor) event logs.
Sysmon is part of Microsoft's Sysinternals suite and provides detailed process, network,
and file activity logging for security monitoring.
"""

import re
import json
import logging
import base64
from typing import Dict, Any, Optional, List
from datetime import datetime
from xml.etree import ElementTree

logger = logging.getLogger(__name__)


# Sysmon Event ID to Event Type mapping
SYSMON_EVENT_IDS = {
    1: ('SYSMON_PROCESS', 'Process Create'),
    2: ('SYSMON_FILE', 'File Creation Time Changed'),
    3: ('SYSMON_NETWORK', 'Network Connection'),
    4: ('SYSMON_ERROR', 'Sysmon Service State Changed'),
    5: ('SYSMON_PROCESS', 'Process Terminated'),
    6: ('SYSMON_IMAGE', 'Driver Loaded'),
    7: ('SYSMON_IMAGE', 'Image Loaded'),
    8: ('SYSMON_CREATE_REMOTE_THREAD', 'Create Remote Thread'),
    9: ('SYSMON_PROCESS_ACCESS', 'Raw Access Read'),
    10: ('SYSMON_PROCESS_ACCESS', 'Process Access'),
    11: ('SYSMON_FILE', 'File Created'),
    12: ('SYSMON_REGISTRY', 'Registry Object Added'),
    13: ('SYSMON_REGISTRY', 'Registry Value Set'),
    14: ('SYSMON_REGISTRY', 'Registry Object Deleted'),
    15: ('SYSMON_FILE', 'File Stream Created'),
    16: ('SYSMON_ERROR', 'Service Configuration Changed'),
    17: ('SYSMON_PIPE_EVENT', 'Named Pipe Created'),
    18: ('SYSMON_PIPE_EVENT', 'Named Pipe Connected'),
    19: ('SYSMON_WMI_FILTER', 'WMI Filter Activated'),
    20: ('SYSMON_WMI', 'WMI Consumer Created'),
    21: ('SYSMON_WMI', 'WMI Consumer Filter Binding'),
    22: ('SYSMON_DNS_QUERY', 'DNS Query'),
    23: ('SYSMON_FILE_DELETE', 'File Delete'),
    24: ('SYSMON_PROCESS', 'Clipboard Changed'),
    25: ('SYSMON_PROCESS_TAMPERING', 'Process Tampering'),
    26: ('SYSMON_FILE', 'File Delete Log'),
    27: ('SYSMON_FILE', 'File Execution'),
}

# Common suspicious process names
SUSPICIOUS_PROCESSES = [
    'mimikatz', 'pwdump', 'procdump', 'lsadump', 'cachedump',
    'metasploit', 'msfconsole', 'msfvenom', 'covenant', 'koadic',
    'empire', 'silenttrinity', 'pupy', 'merlin', 'sliver',
    'cscript.exe', 'wscript.exe', 'powershell.exe', 'cmd.exe',
    'rundll32.exe', 'regsvr32.exe', 'msiexec.exe', 'certutil.exe',
    'bitsadmin.exe', 'whoami.exe', 'net.exe', 'net1.exe',
]

# Suspicious command line patterns
SUSPICIOUS_COMMAND_PATTERNS = [
    # Encoded commands
    r'-enc(odedCommand)?\s+',
    r'-e(ncodedcommand)?\s+',
    r'frombase64string',
    # Suspicious keywords
    r'invoke(-|_)',
    r'iex\s',
    r' downloadstring',
    r' downloadfile',
    r'new-object\s+net\.webclient',
    r'start-process\s+-windowstyle\s+hidden',
    r'-w\s+hidden',
    r'-windowstyle\s+hidden',
    # Reconnaissance
    r'get-process',
    r'get-service',
    r'get-wmiobject',
    r'get-adcomputer',
    r'get-aduser',
    r'get-localuser',
    # Credential access
    r'get-credential',
    r'get-lapspassword',
    r' dump',
    # Lateral movement
    r'new-pssession',
    r'enter-pssession',
    r'wmi',
    r'winrm',
    r'remote',
    # Persistence
    r'reg\s+add',
    r'schtasks\s+/create',
    r'new-scheduledtask',
    # Privilege escalation
    r'bypass',
    r'noLMHash',
    r'ntds\.dit',
    # Data exfiltration
    r'upload',
    r'exfil',
    r'to-web',
    # Obfuscation
    r'\$\{',
    r'\$env:',
    r'\(\$',
]

# Suspicious parent processes (commonly used for lateral movement)
SUSPICIOUS_PARENT_PROCESSES = [
    'cmd.exe', 'powershell.exe', 'cscript.exe', 'wscript.exe',
    'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wmic.exe',
    'certutil.exe', 'msiexec.exe',
]


class SysmonParser:
    """Parser for Windows Sysmon event logs"""
    
    def __init__(self):
        self.suspicious_process_patterns = [
            re.compile(p, re.I) for p in SUSPICIOUS_COMMAND_PATTERNS
        ]
    
    def parse_xml_event(self, xml_string: str) -> Dict[str, Any]:
        """
        Parse a Windows Event XML string into a structured dictionary.
        
        Args:
            xml_string: The raw XML string from Windows Event Log
            
        Returns:
            Dictionary containing parsed event data
        """
        try:
            root = ElementTree.fromstring(xml_string)
            
            # Get system section
            system = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}System')
            if system is None:
                # Try without namespace
                system = root.find('.//System')
            
            # Get event data section
            event_data = root.find('.//EventData')
            if event_data is None:
                event_data = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
            
            if event_data is None:
                # Try UserData section
                event_data = root.find('.//UserData')
            
            # Extract fields
            result = {}
            
            if system is not None:
                # Extract provider info
                provider = system.find('.//Provider')
                if provider is not None:
                    result['provider_name'] = provider.get('Name', '')
                
                # Extract event ID
                event_id_elem = system.find('.//EventID')
                if event_id_elem is not None:
                    result['event_id'] = int(event_id_elem.text or 0)
                
                # Extract level
                level_elem = system.find('.//Level')
                if level_elem is not None:
                    level_map = {
                        '0': 'INFO',  # LogAlways
                        '1': 'CRITICAL',
                        '2': 'ERROR',
                        '3': 'WARNING',
                        '4': 'INFO',
                        '5': 'DEBUG',
                    }
                    result['level'] = level_map.get(level_elem.text, 'INFO')
                
                # Extract time created - use find method instead of attrib
                time_created = system.find('.//TimeCreated')
                if time_created is not None:
                    result['timestamp'] = time_created.get('SystemTime', '')
                
                # Extract computer
                computer = system.find('.//Computer')
                if computer is not None:
                    result['computer'] = computer.text or ''
                
                # Extract channel
                channel = system.find('.//Channel')
                if channel is not None:
                    result['channel'] = channel.text or ''
                
                # Extract security user
                security = system.find('.//Security')
                if security is not None:
                    result['user_name'] = security.get('UserID', '')
            
            # Extract event data items
            if event_data is not None:
                for item in event_data:
                    name = item.get('Name', '')
                    text = item.text or ''
                    
                    # Map common Sysmon field names
                    field_mapping = {
                        'NewProcessName': 'process_path',
                        'ProcessName': 'process_name',
                        'Image': 'process_path',
                        'ImageLoaded': 'process_path',
                        'ParentImage': 'parent_process_path',
                        'ParentCommandLine': 'parent_command_line',
                        'CommandLine': 'process_command_line',
                        'TargetObject': 'registry_key',
                        'DestinationIp': 'destination_ip',
                        'DestinationPort': 'destination_port',
                        'SourceIp': 'source_ip',
                        'SourcePort': 'source_port',
                        'Protocol': 'protocol',
                        'QueryName': 'dns_query',
                        'QueryResults': 'dns_result',
                        'FileName': 'file_name',
                        'TargetFilename': 'file_path',
                        'ProcessId': 'process_id',
                        'ParentProcessId': 'parent_process_id',
                        'Hashes': 'process_hash',
                        'User': 'user_name',
                        'Computer': 'computer',
                    }
                    
                    mapped_name = field_mapping.get(name, name)
                    result[mapped_name] = text
            
            return result
            
        except ElementTree.ParseError as e:
            logger.error(f"Failed to parse XML: {e}")
            return {}
        except Exception as e:
            logger.error(f"Error parsing Sysmon event: {e}")
            return {}
    
    def parse_json_event(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a JSON-formatted Sysmon event.
        
        Args:
            json_data: The JSON dictionary from Sysmon (e.g., via winlogbeat)
            
        Returns:
            Dictionary containing parsed event data
        """
        result = {}
        
        # Extract timestamp
        if '@timestamp' in json_data:
            result['timestamp'] = json_data['@timestamp']
        elif 'time' in json_data:
            result['timestamp'] = json_data['time']
        
        # Extract event info
        if 'winlog' in json_data:
            winlog = json_data['winlog']
            
            result['channel'] = winlog.get('channel', '')
            result['provider_name'] = winlog.get('provider_name', '')
            result['event_id'] = winlog.get('event_id', 0)
            result['computer'] = winlog.get('computer', '')
            result['user_name'] = winlog.get('user', {}).get('name', '')
            
            # Get level/severity
            level = winlog.get('level', 'information')
            level_map = {
                'critical': 'CRITICAL',
                'error': 'ERROR',
                'warning': 'WARNING',
                'information': 'INFO',
                'verbose': 'DEBUG',
            }
            result['level'] = level_map.get(level.lower(), 'INFO')
        
        # Extract event data
        if 'event_data' in json_data:
            event_data = json_data['event_data']
            
            # Map common fields
            field_mapping = {
                'NewProcessName': 'process_path',
                'ProcessName': 'process_name',
                'Image': 'process_path',
                'ImageLoaded': 'process_path',
                'ParentImage': 'parent_process_path',
                'ParentCommandLine': 'parent_command_line',
                'CommandLine': 'process_command_line',
                'TargetObject': 'registry_key',
                'DestinationIp': 'destination_ip',
                'DestinationPort': 'destination_port',
                'SourceIp': 'source_ip',
                'SourcePort': 'source_port',
                'Protocol': 'protocol',
                'QueryName': 'dns_query',
                'QueryResults': 'dns_result',
                'FileName': 'file_name',
                'TargetFilename': 'file_path',
                'ProcessId': 'process_id',
                'ParentProcessId': 'parent_process_id',
                'Hashes': 'process_hash',
            }
            
            for key, value in event_data.items():
                mapped_key = field_mapping.get(key, key)
                result[mapped_key] = value
        
        # Extract message
        if 'message' in json_data:
            result['message'] = json_data['message']
        
        # Extract source IP (from network data if available)
        if 'source' in json_data and isinstance(json_data['source'], dict):
            result['source_ip'] = json_data['source'].get('ip', '')
        
        return result
    
    def parse_plain_text_event(self, text: str) -> Dict[str, Any]:
        """
        Parse a plain text Sysmon-style log entry.
        
        Example input:
        Timestamp: 2026-03-06T14:10:00.000Z
        EventID: 1
        Channel: Microsoft-Windows-Sysmon/Operational
        User: LaptopUser\jsmith
        Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        CommandLine: powershell.exe -EncodedCommand JABzAD0...
        ParentProcess: C:\Windows\Explorer.EXE
        
        Args:
            text: Plain text log entry
            
        Returns:
            Dictionary containing parsed event data
        """
        result = {}
        
        # Parse key-value pairs
        patterns = {
            'timestamp': r'Timestamp:\s*(.+)',
            'event_id': r'EventID:\s*(\d+)',
            'channel': r'Channel:\s*(.+)',
            'provider_name': r'Provider:\s*(.+)',
            'user_name': r'User:\s*(.+)',
            'process_path': r'Process:\s*(.+)',
            'process_name': r'ProcessName:\s*(.+)',
            'command_line': r'CommandLine:\s*(.+)',
            'parent_process': r'ParentProcess:\s*(.+)',
            'parent_process_path': r'ParentImage:\s*(.+)',
            'parent_command_line': r'ParentCommandLine:\s*(.+)',
            'process_id': r'ProcessId:\s*(\d+)',
            'parent_process_id': r'ParentProcessId:\s*(\d+)',
            'destination_ip': r'DestinationIp:\s*(.+)',
            'destination_port': r'DestinationPort:\s*(\d+)',
            'source_ip': r'SourceIp:\s*(.+)',
            'source_port': r'SourcePort:\s*(\d+)',
            'protocol': r'Protocol:\s*(.+)',
            'file_name': r'FileName:\s*(.+)',
            'file_path': r'TargetFilename:\s*(.+)',
            'registry_key': r'TargetObject:\s*(.+)',
            'dns_query': r'QueryName:\s*(.+)',
            'computer': r'Computer:\s*(.+)',
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                
                # Convert numeric fields
                if field in ['event_id', 'destination_port', 'source_port', 'process_id', 'parent_process_id']:
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                
                result[field] = value
        
        # Set level based on event ID
        if 'event_id' in result:
            event_id = result['event_id']
            result['level'] = self._get_level_for_event_id(event_id)
            result['event_type'] = self._get_event_type_for_id(event_id)
        
        # Set service based on channel
        if 'channel' in result:
            result['service'] = self._extract_service_name(result['channel'])
        
        # Extract process name from path if not provided
        if 'process_path' in result and 'process_name' not in result:
            result['process_name'] = self._extract_process_name(result['process_path'])
        
        # Extract parent process name from path if not provided
        if 'parent_process_path' in result and 'parent_process_name' not in result:
            result['parent_process_name'] = self._extract_process_name(result['parent_process_path'])
        
        # Generate message if not present
        if 'message' not in result:
            result['message'] = self._generate_message(result)
        
        return result
    
    def _get_level_for_event_id(self, event_id: int) -> str:
        """Get log level based on Sysmon event ID"""
        # Critical/high-risk events
        if event_id in [1, 8, 10]:  # Process create, remote thread, process access
            return 'INFO'  # Could be suspicious
        elif event_id in [3]:  # Network connection
            return 'INFO'
        elif event_id in [11, 23]:  # File created/deleted
            return 'INFO'
        elif event_id in [12, 13, 14]:  # Registry changes
            return 'INFO'
        elif event_id in [22]:  # DNS query
            return 'INFO'
        return 'INFO'
    
    def _get_event_type_for_id(self, event_id: int) -> str:
        """Get event type string for event ID"""
        if event_id in SYSMON_EVENT_IDS:
            return SYSMON_EVENT_IDS[event_id][0]
        return 'OTHER'
    
    def _extract_service_name(self, channel: str) -> str:
        """Extract service name from Windows Event Channel"""
        if 'Sysmon' in channel:
            return 'Windows-Sysmon'
        elif 'Security' in channel:
            return 'Windows-Security'
        elif 'Application' in channel:
            return 'Windows-Application'
        elif 'System' in channel:
            return 'Windows-System'
        return 'Windows-Event'
    
    def _extract_process_name(self, path: str) -> str:
        """Extract process name from full path"""
        if not path:
            return ''
        # Handle Windows paths
        parts = path.replace('/', '\\').split('\\')
        return parts[-1] if parts else ''
    
    def _generate_message(self, data: Dict[str, Any]) -> str:
        """Generate a human-readable message from parsed data"""
        event_id = data.get('event_id')
        
        if event_id == 1:  # Process Create
            process = data.get('process_name', 'Unknown')
            parent = data.get('parent_process_name', 'Unknown')
            return f"Process created: {process} (Parent: {parent})"
        
        elif event_id == 3:  # Network Connection
            dest_ip = data.get('destination_ip', 'Unknown')
            dest_port = data.get('destination_port', 'Unknown')
            protocol = data.get('protocol', 'TCP')
            process = data.get('process_name', 'Unknown')
            return f"Network connection: {process} -> {dest_ip}:{dest_port} ({protocol})"
        
        elif event_id == 11:  # File Created
            file_path = data.get('file_path', 'Unknown')
            return f"File created: {file_path}"
        
        elif event_id == 12 or event_id == 13:  # Registry
            key = data.get('registry_key', 'Unknown')
            return f"Registry change: {key}"
        
        elif event_id == 22:  # DNS Query
            query = data.get('dns_query', 'Unknown')
            return f"DNS query: {query}"
        
        elif event_id == 23:  # File Delete
            file_path = data.get('file_path', 'Unknown')
            return f"File deleted: {file_path}"
        
        return f"Sysmon Event ID {event_id}"
    
    def detect_threats(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect potential threats in parsed Sysmon data.
        
        Args:
            parsed_data: Dictionary containing parsed event data
            
        Returns:
            List of detected threats with details
        """
        threats = []
        
        # Check for encoded PowerShell commands (CRITICAL)
        command_line = parsed_data.get('process_command_line', '')
        if command_line:
            if re.search(r'-enc(odedcommand)?\s+', command_line, re.I):
                threats.append({
                    'type': 'encoded_powershell',
                    'severity': 'critical',
                    'confidence': 0.95,
                    'description': 'Encoded PowerShell command detected - common attack technique',
                    'recommendation': 'Investigate the encoded command content and origin'
                })
            
            # Check for other suspicious encoded commands
            if re.search(r'(-enc|-e)\s+[A-Za-z0-9+/=]', command_line):
                threats.append({
                    'type': 'encoded_command',
                    'severity': 'high',
                    'confidence': 0.90,
                    'description': 'Potentially encoded/obfuscated command detected',
                    'recommendation': 'Decode and analyze the command content'
                })
        
        # Check for suspicious processes (malware/hacking tools only)
        process_name = parsed_data.get('process_name', '').lower()
        suspicious_tools = [
            'mimikatz', 'pwdump', 'procdump', 'lsadump', 'cachedump',
            'metasploit', 'msfconsole', 'msfvenom', 'covenant', 'koadic',
            'empire', 'silenttrinity', 'pupy', 'merlin', 'sliver',
            'psexec', 'wce.exe', 'gsecdump', 'fgdump', 'nbtenum',
        ]
        if process_name in suspicious_tools:
            threats.append({
                'type': 'suspicious_process',
                'severity': 'critical',
                'confidence': 0.95,
                'description': f'Suspicious/hacking tool executed: {process_name}',
                'recommendation': 'Immediately investigate this process - potential compromise'
            })
        
        # Note: We don't flag powershell.exe, cmd.exe as suspicious by themselves
        # Only the encoded commands are suspicious
        
        # Check for suspicious parent processes (when spawning suspicious tools)
        parent_process = parsed_data.get('parent_process_name', '').lower()
        # Only flag if parent is suspicious AND the child is also suspicious
        if parent_process and process_name in suspicious_tools:
            threats.append({
                'type': 'suspicious_parent_process',
                'severity': 'high',
                'confidence': 0.80,
                'description': f'Suspicious tool {process_name} spawned from: {parent_process}',
                'recommendation': 'Investigate parent process legitimacy'
            })
        
        # Check for suspicious command patterns (only if we have a command line)
        if command_line:
            suspicious_cmd_patterns = [
                (r'invoke-', 'PowerShell Invoke command - possible lateral movement'),
                (r'iex\s', 'PowerShell IEX command - possible download cradle'),
                (r'downloadstring', 'PowerShell download string - possible download cradle'),
                (r'downloadfile', 'PowerShell download file - possible malware download'),
                (r'new-object\s+net\.webclient', 'WebClient object - possible download cradle'),
                (r'start-process\s+-windowstyle\s+hidden', 'Hidden process start - possible stealth activity'),
                (r'-w\s+hidden', 'Hidden window - possible stealth activity'),
                (r'-nop\s+-w\s+hidden', 'Bypass + hidden - common attack technique'),
                (r'executionpolicy\s+bypass', 'Execution policy bypass - possible malware execution'),
            ]
            
            for pattern, description in suspicious_cmd_patterns:
                if re.search(pattern, command_line, re.I):
                    # Don't add duplicate if already detected as encoded_powershell
                    if not any(t['type'] == 'encoded_powershell' for t in threats):
                        threats.append({
                            'type': 'suspicious_command',
                            'severity': 'high',
                            'confidence': 0.75,
                            'description': description,
                            'recommendation': 'Review command for malicious intent'
                        })
                    break
        
        # Check for suspicious network connections
        dest_ip = parsed_data.get('destination_ip', '')
        dest_port = parsed_data.get('destination_port', 0)
        if dest_ip and dest_port:
            # Check for suspicious ports
            suspicious_ports = {
                4444: 'Metasploit default',
                5555: 'Metasploit/koadic',
                6667: 'IRC (potential bot)',
                31337: 'Back Orifice',
                1337: 'Leet port',
            }
            if dest_port in suspicious_ports:
                threats.append({
                    'type': 'suspicious_network',
                    'severity': 'critical',
                    'confidence': 0.90,
                    'description': f'Connection to suspicious port {dest_port}: {suspicious_ports[dest_port]}',
                    'recommendation': 'Block connection immediately and investigate'
                })
            
            # Check for suspicious IPs (internal scan, etc.)
            if dest_ip.startswith(('10.', '172.16.', '192.168.')):
                # Internal IP - check if from unusual process
                process = parsed_data.get('process_name', '').lower()
                if 'nmap' in process or 'scan' in process:
                    threats.append({
                        'type': 'network_scan',
                        'severity': 'critical',
                        'confidence': 0.90,
                        'description': 'Potential network scanning activity detected',
                        'recommendation': 'Investigate source and destination'
                    })
        
        # Check for suspicious registry modifications
        registry_key = parsed_data.get('registry_key', '')
        if registry_key:
            suspicious_keys = [
                (r'run\\', 'Run registry key - possible persistence'),
                (r'software\\microsoft\\windows\\currentversion\\run', 'Run key - common persistence mechanism'),
                (r'winlogon\\', 'Winlogon key - possible credential theft'),
                (r'services\\', 'Services key - possible service installation'),
            ]
            for pattern, description in suspicious_keys:
                if re.search(pattern, registry_key, re.I):
                    threats.append({
                        'type': 'registry_persistence',
                        'severity': 'high',
                        'confidence': 0.85,
                        'description': f'Potential persistence via registry: {description}',
                        'recommendation': 'Verify legitimacy of registry modification'
                    })
                    break
        
        # Check for DNS queries to suspicious domains
        dns_query = parsed_data.get('dns_query', '').lower()
        if dns_query:
            suspicious_domains = [
                ('pastebin', 'Pastebin - possible malware hosting'),
                ('gist.github', 'GitHub Gist - possible malware hosting'),
                ('raw.githubusercontent', 'GitHub raw - possible malware hosting'),
                ('.tk', 'TLD .tk - common attacker domain'),
                ('.ml', 'TLD .ml - common attacker domain'),
                ('.ga', 'TLD .ga - common attacker domain'),
                ('.cf', 'TLD .cf - common attacker domain'),
                ('.gq', 'TLD .gq - common attacker domain'),
            ]
            for domain, description in suspicious_domains:
                if domain in dns_query:
                    threats.append({
                        'type': 'suspicious_dns',
                        'severity': 'medium',
                        'confidence': 0.70,
                        'description': f'Suspicious DNS query: {description}',
                        'recommendation': 'Investigate DNS query destination'
                    })
                    break
        
        return threats
    
    def decode_base64_command(self, encoded_command: str) -> Optional[str]:
        """
        Attempt to decode a base64 encoded PowerShell command.
        
        Args:
            encoded_command: Base64 encoded string
            
        Returns:
            Decoded command string or None if decoding fails
        """
        try:
            # Try standard base64
            decoded = base64.b64decode(encoded_command).decode('utf-16-le')
            return decoded
        except Exception:
            pass
        
        try:
            # Try single round base64
            decoded = base64.b64decode(encoded_command).decode('utf-8')
            return decoded
        except Exception:
            pass
        
        return None


# Singleton instance
sysmon_parser = SysmonParser()


def get_sysmon_parser() -> SysmonParser:
    """Get the Sysmon parser instance"""
    return sysmon_parser


def parse_sysmon_log(log_input: Any, format: str = 'auto') -> Dict[str, Any]:
    """
    Main entry point for parsing Sysmon logs.
    
    Args:
        log_input: The log data (string or dict)
        format: Format of the input ('xml', 'json', 'text', 'auto')
        
    Returns:
        Dictionary containing parsed event data
    """
    parser = get_sysmon_parser()
    
    if format == 'auto':
        # Auto-detect format
        if isinstance(log_input, dict):
            format = 'json'
        elif log_input.strip().startswith('<'):
            format = 'xml'
        elif log_input.strip().startswith('{'):
            format = 'json'
        else:
            format = 'text'
    
    if format == 'xml':
        return parser.parse_xml_event(log_input)
    elif format == 'json':
        return parser.parse_json_event(log_input)
    elif format == 'text':
        return parser.parse_plain_text_event(log_input)
    
    return {}

