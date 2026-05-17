"""
AI Log Monitoring & Security Detection Platform
AI Engine - Threat Detector Service
"""

import re
import logging
from typing import Dict, List, Optional, Any
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count, Max

logger = logging.getLogger(__name__)


class ThreatDetector:
    """Pattern-based threat detection service"""
    
    # Known malicious IP patterns (simplified)
    KNOWN_MALICIOUS_PATTERNS = [
        r'^10\.0\.0\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
    ]
    
    # Brute force patterns
    BRUTE_FORCE_PATTERNS = [
        r'failed login',
        r'authentication failed',
        r'invalid credentials',
        r'login failed',
        r'wrong password',
        r'access denied',
        r'user not found',
        r'account locked',
    ]
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        r'union.*select',
        r"' or '1'='1",
        r'exec\s*\(',
        r'drop\s+table',
        r'insert\s+into',
        r'delete\s+from',
        r'update\s+.*set',
        r'mysql_fetch',
        r'sql\s+syntax',
        r'postgresql\s+error',
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r'<script',
        r'javascript:',
        r'onerror=',
        r'onload=',
        r'onclick=',
        r'alert\(',
        r'<img.*src=',
    ]
    
    # DDoS patterns
    DDOS_PATTERNS = [
        r'too many requests',
        r'rate limit',
        r'request timeout',
        r'connection refused',
        r'service unavailable',
    ]
    
    # Unauthorized access patterns
    UNAUTHORIZED_PATTERNS = [
        r'access denied',
        r'forbidden',
        r'unauthorized',
        r'permission denied',
        r'not allowed',
        r'invalid token',
        r'expired session',
    ]
    
    # === Windows Sysmon specific patterns ===
    
    # Encoded PowerShell command patterns (CRITICAL)
    ENCODED_POWERSHELL_PATTERNS = [
        r'-enc(odedcommand)?\s+',
        r'frombase64string',
        r'\[System\.Convert\]::FromBase64String',
    ]
    
    # Suspicious PowerShell patterns
    SUSPICIOUS_POWERSHELL_PATTERNS = [
        r'invoke-',
        r'invoke\(',
        r'iex\s',
        r' downloadstring',
        r' downloadfile',
        r'new-object\s+net\.webclient',
        r'start-process\s+-windowstyle\s+hidden',
        r'-w\s+hidden',
        r'-windowstyle\s+hidden',
        r'-nop\s+-w\s+hidden',
        r'executionpolicy\s+bypass',
    ]
    
    # Suspicious processes (excludes common legitimate Windows processes like powershell, cmd)
    SUSPICIOUS_PROCESS_PATTERNS = [
        r'mimikatz',
        r'pwdump',
        r'procdump',
        r'lsadump',
        r'cachedump',
        r'metasploit',
        r'msfconsole',
        r'msfvenom',
        r'covenant',
        r'koadic',
        r'empire',
        r'silenttrinity',
        r'pupy',
        r'merlin',
        r'sliver',
        r'covenant',
        r'koadic',
        r'psexec',
        r'wce.exe',
        r'gsecdump',
        r'fgdump',
        r'raven',
        r'nbtenum',
        r'smbexec',
        r'wmiexec',
    ]
    
    # Suspicious parent processes (commonly used for lateral movement)
    SUSPICIOUS_PARENT_PATTERNS = [
        r'cmd\.exe',
        r'powershell\.exe',
        r'cscript\.exe',
        r'wscript\.exe',
        r'rundll32\.exe',
        r'regsvr32\.exe',
        r'mshta\.exe',
        r'wmic\.exe',
        r'certutil\.exe',
        r'msiexec\.exe',
    ]
    
    # Suspicious network ports
    SUSPICIOUS_PORTS = {
        4444: 'Metasploit default',
        5555: 'Metasploit/koadic',
        6667: 'IRC (potential bot)',
        31337: 'Back Orifice',
        1337: 'Leet port',
        8080: 'Common proxy/HTTP alt',
        8443: 'HTTPS alt',
        4444: 'Metasploit',
    }
    
    # Suspicious registry keys for persistence
    SUSPICIOUS_REGISTRY_PATTERNS = [
        r'software\\microsoft\\windows\\currentversion\\run',
        r'software\\microsoft\\windows\\currentversion\\runonce',
        r'software\\microsoft\\windows\\currentversion\\explorer\\advanced',
        r'system\\currentcontrolset\\services',
        r'software\\classes\\exefile\\shell\\open\\command',
        r'software\\classes\\comfile\\shell\\open\\command',
    ]
    
    # Suspicious DNS patterns
    SUSPICIOUS_DNS_PATTERNS = [
        r'pastebin',
        r'gist\.github',
        r'raw\.githubusercontent',
        r'\.tk$',
        r'\.ml$',
        r'\.ga$',
        r'\.cf$',
        r'\.gq$',
    ]
    
    def __init__(self):
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficiency"""
        self.brute_force_re = [re.compile(p, re.I) for p in self.BRUTE_FORCE_PATTERNS]
        self.sql_injection_re = [re.compile(p, re.I) for p in self.SQL_INJECTION_PATTERNS]
        self.xss_re = [re.compile(p, re.I) for p in self.XSS_PATTERNS]
        self.ddos_re = [re.compile(p, re.I) for p in self.DDOS_PATTERNS]
        self.unauthorized_re = [re.compile(p, re.I) for p in self.UNAUTHORIZED_PATTERNS]
        
        # Sysmon patterns
        self.encoded_powershell_re = [re.compile(p, re.I) for p in self.ENCODED_POWERSHELL_PATTERNS]
        self.suspicious_powershell_re = [re.compile(p, re.I) for p in self.SUSPICIOUS_POWERSHELL_PATTERNS]
        self.suspicious_process_re = [re.compile(p, re.I) for p in self.SUSPICIOUS_PROCESS_PATTERNS]
        self.suspicious_parent_re = [re.compile(p, re.I) for p in self.SUSPICIOUS_PARENT_PATTERNS]
        self.suspicious_registry_re = [re.compile(p, re.I) for p in self.SUSPICIOUS_REGISTRY_PATTERNS]
        self.suspicious_dns_re = [re.compile(p, re.I) for p in self.SUSPICIOUS_DNS_PATTERNS]
    
    def detect_threat(self, log_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect threats in a log entry"""
        
        # First, check if this is a Sysmon event
        if self._is_sysmon_event(log_data):
            return self._detect_sysmon_threat(log_data)
        
        # Standard log analysis
        message = log_data.get('message', '').lower()
        level = log_data.get('level', '').upper()
        ip = log_data.get('ip_address', '')
        
        # Check SQL Injection
        if self._match_patterns(message, self.sql_injection_re):
            return {
                'type': 'sql_injection',
                'severity': 'critical',
                'description': 'SQL injection attempt detected'
            }
        
        # Check XSS
        if self._match_patterns(message, self.xss_re):
            return {
                'type': 'xss_attempt',
                'severity': 'high',
                'description': 'XSS attempt detected'
            }
        
        # Check Brute Force
        if self._match_patterns(message, self.brute_force_re):
            return {
                'type': 'brute_force',
                'severity': 'high',
                'description': 'Failed login attempt detected'
            }
        
        # Check DDoS
        if self._match_patterns(message, self.ddos_re):
            return {
                'type': 'ddos',
                'severity': 'critical',
                'description': 'Potential DDoS attack detected'
            }
        
        # Check Unauthorized Access
        if self._match_patterns(message, self.unauthorized_re):
            return {
                'type': 'unauthorized_access',
                'severity': 'medium',
                'description': 'Unauthorized access attempt detected'
            }
        
        # Check for suspicious IP
        if self._is_suspicious_ip(ip):
            return {
                'type': 'suspicious_ip',
                'severity': 'medium',
                'description': 'Access from suspicious IP range'
            }
        
        return None
    
    def _is_sysmon_event(self, log_data: Dict[str, Any]) -> bool:
        """Check if this is a Sysmon/Windows Event log"""
        channel = log_data.get('channel', '').lower()
        event_id = log_data.get('event_id')
        event_type = log_data.get('event_type', '')
        service = log_data.get('service', '').lower()
        
        return (
            event_id is not None or
            'sysmon' in channel or
            'security' in channel or
            'windows' in service or
            'SYSMON' in event_type
        )
    
    def _detect_sysmon_threat(self, log_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect threats specific to Windows Sysmon events"""
        
        # Check encoded PowerShell commands (most critical)
        command_line = log_data.get('process_command_line', '')
        if command_line:
            if self._match_patterns(command_line, self.encoded_powershell_re):
                return {
                    'type': 'encoded_powershell',
                    'severity': 'critical',
                    'description': 'Encoded PowerShell command detected - common attack technique'
                }
            
            # Check suspicious PowerShell usage
            if self._match_patterns(command_line, self.suspicious_powershell_re):
                return {
                    'type': 'suspicious_powershell',
                    'severity': 'high',
                    'description': 'Suspicious PowerShell command detected'
                }
        
        # Check suspicious process names
        process_name = log_data.get('process_name', '')
        if process_name:
            if self._match_patterns(process_name, self.suspicious_process_re):
                return {
                    'type': 'suspicious_process',
                    'severity': 'critical',
                    'description': f'Suspicious process executed: {process_name}'
                }
        
        # Check suspicious parent processes
        parent_process = log_data.get('parent_process_name', '')
        if parent_process:
            if self._match_patterns(parent_process, self.suspicious_parent_re):
                return {
                    'type': 'suspicious_parent_process',
                    'severity': 'high',
                    'description': f'Process spawned from suspicious parent: {parent_process}'
                }
        
        # Check suspicious network connections
        dest_port = log_data.get('destination_port')
        if dest_port and dest_port in self.SUSPICIOUS_PORTS:
            return {
                'type': 'suspicious_network',
                'severity': 'high',
                'description': f'Connection to suspicious port {dest_port}: {self.SUSPICIOUS_PORTS[dest_port]}'
            }
        
        # Check suspicious registry modifications
        registry_key = log_data.get('registry_key', '')
        if registry_key:
            if self._match_patterns(registry_key, self.suspicious_registry_re):
                return {
                    'type': 'registry_persistence',
                    'severity': 'critical',
                    'description': f'Potential persistence mechanism via registry: {registry_key[:100]}'
                }
        
        # Check suspicious DNS queries
        dns_query = log_data.get('dns_query', '')
        if dns_query:
            if self._match_patterns(dns_query, self.suspicious_dns_re):
                return {
                    'type': 'suspicious_dns',
                    'severity': 'medium',
                    'description': f'Suspicious DNS query: {dns_query}'
                }
        
        return None
    
    def check_brute_force(self, ip_address: str, minutes: int = 5, threshold: int = 5) -> bool:
        """Check if IP is attempting brute force"""
        
        from apps.logs.models import Log
        
        since = timezone.now() - timedelta(minutes=minutes)
        
        failed_logins = Log.objects.filter(
            ip_address=ip_address,
            timestamp__gte=since,
            message__icontains='failed'
        ).exclude(
            message__icontains='success'
        ).count()
        
        return failed_logins >= threshold
    
    def check_repeated_errors(self, service: str, minutes: int = 10, threshold: int = 10) -> bool:
        """Check if service is generating repeated errors"""
        
        from apps.logs.models import Log
        
        since = timezone.now() - timedelta(minutes=minutes)
        
        error_count = Log.objects.filter(
            service=service,
            timestamp__gte=since,
            level__in=['ERROR', 'CRITICAL']
        ).count()
        
        return error_count >= threshold
    
    def check_suspicious_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get IPs with most failed login attempts"""
        
        from apps.logs.models import Log
        
        suspicious = Log.objects.filter(
            message__icontains='failed'
        ).exclude(
            message__icontains='success'
        ).values('ip_address').annotate(
            attempt_count=Count('id'),
            last_attempt=Max('timestamp')
        ).order_by('-attempt_count')[:limit]
        
        return list(suspicious)
    
    def _match_patterns(self, text: str, patterns: List[re.Pattern]) -> bool:
        """Check if text matches any pattern"""
        return any(p.search(text) for p in patterns)
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is in suspicious range"""
        for pattern in self.KNOWN_MALICIOUS_PATTERNS:
            if re.match(pattern, ip):
                return True
        return False


# Singleton instance
threat_detector = ThreatDetector()


def get_threat_detector() -> ThreatDetector:
    """Get the threat detector instance"""
    return threat_detector

