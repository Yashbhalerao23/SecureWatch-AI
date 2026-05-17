"""
Web Scanner - Technology Detection & Security Analysis
"""
import re
import requests
import socket
from typing import Dict, List, Any
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class WebScanner:
    """Scan websites for technologies and security issues"""
    
    def __init__(self):
        self.timeout = 10
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def scan_website(self, url: str) -> Dict[str, Any]:
        """Full website scan"""
        result = {
            'url': url,
            'technologies': [],
            'security_issues': [],
            'open_ports': [],
            'headers': {},
            'status_code': None,
            'ssl_enabled': False
        }
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=True)
            result['status_code'] = response.status_code
            result['headers'] = dict(response.headers)
            result['ssl_enabled'] = url.startswith('https')
            
            # Detect technologies
            result['technologies'] = self._detect_technologies(response)
            
            # Check security
            result['security_issues'] = self._check_security(response, url)
            
            # Port scan
            hostname = urlparse(url).hostname
            if hostname:
                result['open_ports'] = self._scan_ports(hostname)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _detect_technologies(self, response) -> List[Dict[str, str]]:
        """Detect web technologies"""
        techs = []
        html = response.text.lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Server
        if 'server' in headers:
            server = headers['server']
            if 'nginx' in server.lower():
                techs.append({'name': 'Nginx', 'category': 'Web Server', 'version': server})
            elif 'apache' in server.lower():
                techs.append({'name': 'Apache', 'category': 'Web Server', 'version': server})
            elif 'iis' in server.lower():
                techs.append({'name': 'IIS', 'category': 'Web Server', 'version': server})
        
        # Frameworks
        if 'django' in html or 'csrftoken' in html:
            techs.append({'name': 'Django', 'category': 'Framework', 'version': 'Unknown'})
        if 'react' in html or '_react' in html:
            techs.append({'name': 'React', 'category': 'JavaScript Framework', 'version': 'Unknown'})
        if 'vue' in html or 'vue.js' in html:
            techs.append({'name': 'Vue.js', 'category': 'JavaScript Framework', 'version': 'Unknown'})
        if 'angular' in html or 'ng-' in html:
            techs.append({'name': 'Angular', 'category': 'JavaScript Framework', 'version': 'Unknown'})
        if 'jquery' in html:
            match = re.search(r'jquery[/-](\d+\.\d+\.\d+)', html)
            version = match.group(1) if match else 'Unknown'
            techs.append({'name': 'jQuery', 'category': 'JavaScript Library', 'version': version})
        if 'bootstrap' in html:
            techs.append({'name': 'Bootstrap', 'category': 'CSS Framework', 'version': 'Unknown'})
        if 'tailwind' in html:
            techs.append({'name': 'Tailwind CSS', 'category': 'CSS Framework', 'version': 'Unknown'})
        
        # CMS
        if 'wp-content' in html or 'wordpress' in html:
            techs.append({'name': 'WordPress', 'category': 'CMS', 'version': 'Unknown'})
        if 'joomla' in html:
            techs.append({'name': 'Joomla', 'category': 'CMS', 'version': 'Unknown'})
        if 'drupal' in html:
            techs.append({'name': 'Drupal', 'category': 'CMS', 'version': 'Unknown'})
        
        # Analytics
        if 'google-analytics' in html or 'gtag' in html:
            techs.append({'name': 'Google Analytics', 'category': 'Analytics', 'version': 'Unknown'})
        
        # CDN
        if 'cloudflare' in headers.get('server', '').lower():
            techs.append({'name': 'Cloudflare', 'category': 'CDN', 'version': 'Unknown'})
        
        # Programming Language
        if 'x-powered-by' in headers:
            powered = headers['x-powered-by'].lower()
            if 'php' in powered:
                techs.append({'name': 'PHP', 'category': 'Programming Language', 'version': powered})
            elif 'asp.net' in powered:
                techs.append({'name': 'ASP.NET', 'category': 'Programming Language', 'version': powered})
        
        return techs
    
    def _check_security(self, response, url: str) -> List[Dict[str, str]]:
        """Check for security issues"""
        issues = []
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Missing security headers
        if 'strict-transport-security' not in headers:
            issues.append({
                'severity': 'medium',
                'issue': 'Missing HSTS Header',
                'description': 'Site does not enforce HTTPS',
                'recommendation': 'Add Strict-Transport-Security header'
            })
        
        if 'x-frame-options' not in headers:
            issues.append({
                'severity': 'medium',
                'issue': 'Missing X-Frame-Options',
                'description': 'Site vulnerable to clickjacking',
                'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
            })
        
        if 'x-content-type-options' not in headers:
            issues.append({
                'severity': 'low',
                'issue': 'Missing X-Content-Type-Options',
                'description': 'MIME type sniffing possible',
                'recommendation': 'Add X-Content-Type-Options: nosniff'
            })
        
        if 'content-security-policy' not in headers:
            issues.append({
                'severity': 'high',
                'issue': 'Missing Content-Security-Policy',
                'description': 'No CSP protection against XSS',
                'recommendation': 'Implement Content-Security-Policy header'
            })
        
        # Check for exposed info
        if 'server' in headers:
            issues.append({
                'severity': 'low',
                'issue': 'Server Header Exposed',
                'description': f'Server version disclosed: {headers["server"]}',
                'recommendation': 'Hide server version information'
            })
        
        if 'x-powered-by' in headers:
            issues.append({
                'severity': 'low',
                'issue': 'X-Powered-By Header Exposed',
                'description': f'Technology disclosed: {headers["x-powered-by"]}',
                'recommendation': 'Remove X-Powered-By header'
            })
        
        # Check SSL
        if not url.startswith('https'):
            issues.append({
                'severity': 'critical',
                'issue': 'No HTTPS',
                'description': 'Site not using SSL/TLS encryption',
                'recommendation': 'Enable HTTPS with valid SSL certificate'
            })
        
        return issues
    
    def _scan_ports(self, hostname: str) -> List[Dict[str, Any]]:
        """Scan common ports"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        
        open_ports = []
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                
                if result == 0:
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'open',
                        'risk': self._get_port_risk(port)
                    })
                sock.close()
            except:
                pass
        
        return open_ports
    
    def _get_port_risk(self, port: int) -> str:
        """Get risk level for open port"""
        high_risk = [21, 23, 3389, 445]  # FTP, Telnet, RDP, SMB
        medium_risk = [22, 3306, 5432, 6379, 27017]  # SSH, Databases
        
        if port in high_risk:
            return 'high'
        elif port in medium_risk:
            return 'medium'
        return 'low'


def scan_website(url: str) -> Dict[str, Any]:
    """Scan a website"""
    scanner = WebScanner()
    return scanner.scan_website(url)
