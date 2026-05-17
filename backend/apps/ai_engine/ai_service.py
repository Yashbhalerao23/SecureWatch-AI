"""
AI Log Monitoring & Security Detection Platform
AI Engine Service - Enhanced with Vulnerability Detection and Chatbot
"""

import os
import json
import logging
import requests
import time
from typing import Dict, List, Optional, Any
from collections import deque
from threading import Lock

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self, max_requests_per_minute=15):
        self.max_requests = max_requests_per_minute
        self.requests = deque()
        self.lock = Lock()
    
    def can_make_request(self) -> bool:
        """Check if we can make a request"""
        with self.lock:
            now = time.time()
            # Remove requests older than 1 minute
            while self.requests and self.requests[0] < now - 60:
                self.requests.popleft()
            
            return len(self.requests) < self.max_requests
    
    def add_request(self):
        """Record a new request"""
        with self.lock:
            self.requests.append(time.time())
    
    def get_remaining_requests(self) -> int:
        """Get remaining requests in current minute"""
        with self.lock:
            now = time.time()
            while self.requests and self.requests[0] < now - 60:
                self.requests.popleft()
            return self.max_requests - len(self.requests)


class AIService:
    """AI Service for log analysis, vulnerability detection, and chatbot"""
    
    def __init__(self):
        self.provider = os.getenv('AI_PROVIDER', 'ollama').lower()
        # Log the provider being used
        logger.info(f"AI Provider from environment: {self.provider}")
        
        # Default model based on provider
        if self.provider == 'ollama':
            self.model = os.getenv('OLLAMA_MODEL', 'llama2')
        elif self.provider == 'gemini':
            self.model = os.getenv('AI_MODEL', 'gemini-2.5-flash')
        else:
            self.model = os.getenv('AI_MODEL', 'gpt-3.5-turbo')
        
        self.api_key = os.getenv('OPENAI_API_KEY') or os.getenv('GEMINI_API_KEY')
        logger.info(f"API Key present: {bool(self.api_key)}")
        
        # Ollama configuration (no API key needed)
        self.ollama_base_url = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        self.ollama_timeout = int(os.getenv('OLLAMA_TIMEOUT', '120'))
        
        self.enabled = os.getenv('AI_ANALYSIS_ENABLED', 'True') == 'True'
        self.client = None
        self.has_ai = False
        
        # Rate limiter for Gemini (15 RPM free tier)
        self.rate_limiter = RateLimiter(max_requests_per_minute=15)
        
        # Check if AI_ANALYSIS_ENABLED is explicitly False
        if not self.enabled:
            logger.warning("AI Analysis is disabled via AI_ANALYSIS_ENABLED setting")
            # Still allow pattern-based analysis
            self.enabled = True
            return
        
        # For Ollama, no API key is needed
        if self.provider == 'ollama':
            self.has_ai = True
            self.client = "ollama"  # Placeholder to indicate Ollama is available
            logger.info(f"Initialized Ollama client with model {self.model} at {self.ollama_base_url}")
            return
        
        # For other providers (OpenAI, Gemini), API key is required
        if not self.api_key:
            logger.warning("No API key configured - using pattern-based fallback analysis")
            self.enabled = True
            self.has_ai = False
            return
        
        # Initialize the client - this sets has_ai to True if successful
        self._init_client()
    
    def _init_client(self):
        """Initialize the AI client"""
        logger.info(f"Initializing client for provider: {self.provider}")
        try:
            if self.provider == 'openai':
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
                self.has_ai = True
                logger.info(f"Initialized OpenAI client with model {self.model}")
            elif self.provider == 'gemini':
                from google import genai
                self.client = genai.Client(api_key=self.api_key)
                self.has_ai = True
                logger.info(f"Initialized Gemini client with model {self.model}")
            else:
                logger.error(f"Unknown AI provider: {self.provider}")
        except ImportError as e:
            logger.error(f"Failed to import AI client: {e}")
        except Exception as e:
            logger.error(f"Failed to initialize AI client: {e}")
    
    def analyze_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single log entry for security threats"""
        
        if self.has_ai and self.client:
            prompt = self._build_analysis_prompt(log_data)
            
            try:
                if self.provider == 'openai':
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {
                                "role": "system",
                                "content": "You are a security analyst specializing in log analysis. Analyze the following log entry for potential security threats. Return your analysis in JSON format."
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        temperature=0.3,
                        max_tokens=500
                    )
                    result = response.choices[0].message.content
                    return self._parse_ai_response(result)
                
                elif self.provider == 'gemini':
                    response = self.client.models.generate_content(
                        model=f'models/{self.model}',
                        contents=prompt
                    )
                    return self._parse_ai_response(response.text)
                
                elif self.provider == 'ollama':
                    return self._call_ollama(prompt, "analyze")
            
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
        
        # Fallback to pattern-based analysis
        return self._generate_fallback_analysis(log_data)
    
    def _call_ollama(self, prompt: str, mode: str = "analyze") -> Dict[str, Any]:
        """Make a request to Ollama API"""
        try:
            url = f"{self.ollama_base_url}/api/generate"
            
            # Build the request payload
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3 if mode == "analyze" else 0.7,
                    "num_predict": 500 if mode == "analyze" else 1000,
                }
            }
            
            response = requests.post(url, json=payload, timeout=self.ollama_timeout)
            
            if response.status_code == 200:
                result = response.json()
                content = result.get('response', '')
                
                if mode == "analyze":
                    return self._parse_ai_response(content)
                elif mode == "chat":
                    return {
                        'success': True,
                        'response': content,
                        'mode': 'ai'
                    }
                elif mode == "manual":
                    return self._parse_manual_response(content)
            else:
                logger.error(f"Ollama API error: {response.status_code} - {response.text}")
        
        except requests.exceptions.ConnectionError:
            logger.error(f"Could not connect to Ollama at {self.ollama_base_url}. Make sure Ollama is running.")
        except requests.exceptions.Timeout:
            logger.error(f"Ollama request timed out after {self.ollama_timeout} seconds")
        except Exception as e:
            logger.error(f"Ollama request failed: {e}")
        
        return {}
    
    def analyze_logs_batch(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze multiple logs"""
        
        results = []
        for log in logs:
            result = self.analyze_log(log)
            results.append(result)
        
        return results
    
    def analyze_manual(self, log_text: str) -> Dict[str, Any]:
        """Analyze manually provided log text"""
        
        logger.info(f"Manual analysis - has_ai: {self.has_ai}, provider: {self.provider}")
        
        if self.has_ai and self.client:
            prompt = f"""Analyze the following log text for security issues:

{log_text}

Provide your analysis in JSON format with the following structure:
{{
    "threat_detected": true/false,
    "threat_type": "type of threat or null",
    "severity": "low/medium/high/critical or null",
    "confidence": 0.0-1.0,
    "description": "explanation of findings",
    "recommendations": "security recommendations"
}}
"""
            
            try:
                logger.info(f"Sending request to {self.provider}...")
                
                if self.provider == 'openai':
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {
                                "role": "system",
                                "content": "You are a security analyst specializing in log analysis. Analyze logs for security threats and explain them in plain English."
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        temperature=0.3,
                        max_tokens=800
                    )
                    result = response.choices[0].message.content
                    parsed = self._parse_manual_response(result)
                    parsed['mode'] = 'ai'
                    parsed['remaining_requests'] = None
                    logger.info("OpenAI analysis successful")
                    return parsed
                
                elif self.provider == 'gemini':
                    if not self.rate_limiter.can_make_request():
                        logger.warning("Rate limit exceeded")
                        return {
                            'threat_detected': False,
                            'threat_type': None,
                            'severity': None,
                            'confidence': 0.0,
                            'description': '⚠️ Rate limit reached. Please wait a moment.',
                            'recommendations': f'Gemini free tier: 15 requests/minute. Remaining: {self.rate_limiter.get_remaining_requests()}',
                            'mode': 'rate_limit',
                            'remaining_requests': self.rate_limiter.get_remaining_requests()
                        }
                    
                    self.rate_limiter.add_request()
                    response = self.client.models.generate_content(
                        model=f'models/{self.model}',
                        contents=prompt
                    )
                    parsed = self._parse_manual_response(response.text)
                    parsed['mode'] = 'ai'
                    parsed['remaining_requests'] = self.rate_limiter.get_remaining_requests()
                    logger.info(f"Gemini analysis successful. Remaining requests: {parsed['remaining_requests']}")
                    return parsed
                
                elif self.provider == 'ollama':
                    result = self._call_ollama(prompt, "manual")
                    if result:
                        result['mode'] = 'ai'
                        logger.info("Ollama analysis successful")
                        return result
            
            except Exception as e:
                logger.error(f"Manual AI analysis failed: {e}", exc_info=True)
                return {
                    'threat_detected': False,
                    'threat_type': None,
                    'severity': None,
                    'confidence': 0.0,
                    'description': f'⚠️ AI analysis failed: {str(e)}',
                    'recommendations': 'Check API key and network connection',
                    'mode': 'error'
                }
        
        logger.info("Using pattern-based fallback analysis")
        return self._generate_manual_fallback_analysis(log_text)
    
    def detect_vulnerabilities(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect vulnerabilities in log entries using AI"""
        
        message = log_data.get('message', '').lower()
        level = log_data.get('level', '').upper()
        service = log_data.get('service', '').lower()
        
        vulnerabilities = []
        
        # Pattern-based vulnerability detection
        vulnerability_patterns = {
            'sql_injection': {
                'patterns': ['sql syntax', 'sql injection', 'unterminated', 'mysql_fetch', 
                            'postgresql error', 'ORA-', 'You have an error in your SQL'],
                'severity': 'critical',
                'cwe': 'CWE-89',
                'description': 'SQL Injection vulnerability detected',
                'recommendation': 'Use parameterized queries, validate input, employ WAF'
            },
            'xss_attempt': {
                'patterns': ['<script', 'javascript:', 'onerror=', 'onload=', 
                            'eval(', 'innerHTML', 'document.cookie'],
                'severity': 'high',
                'cwe': 'CWE-79',
                'description': 'Cross-Site Scripting (XSS) attempt detected',
                'recommendation': 'Sanitize user input, use Content Security Policy'
            },
            'command_injection': {
                'patterns': ['system(', 'exec(', 'shell_exec', 'passthru', 
                            'proc_open', '|', '&&', ';'],
                'severity': 'critical',
                'cwe': 'CWE-78',
                'description': 'Command Injection vulnerability detected',
                'recommendation': 'Avoid shell commands, use safe APIs, validate inputs'
            },
            'path_traversal': {
                'patterns': ['../', '..\\', '/etc/passwd', '/etc/shadow',
                            'windows/system32', 'boot.ini'],
                'severity': 'high',
                'cwe': 'CWE-22',
                'description': 'Path Traversal vulnerability detected',
                'recommendation': 'Validate and sanitize file paths, use whitelisting'
            },
            'weak_crypto': {
                'patterns': ['md5', 'sha1', 'des ', 'rc4', 'weak cipher'],
                'severity': 'medium',
                'cwe': 'CWE-327',
                'description': 'Weak cryptographic algorithm detected',
                'recommendation': 'Use strong encryption (AES-256, SHA-256+)'
            },
            'sensitive_data': {
                'patterns': ['password=', 'api_key=', 'secret=', 'token=', 
                            'authorization:', 'bearer ', 'private_key'],
                'severity': 'high',
                'cwe': 'CWE-200',
                'description': 'Sensitive data exposure detected',
                'recommendation': 'Encrypt sensitive data, use secure storage, mask logs'
            },
            'authentication_bypass': {
                'patterns': ['authentication failed', 'login failed', 'access denied',
                            'unauthorized', 'forbidden', 'permission denied'],
                'severity': 'high',
                'cwe': 'CWE-287',
                'description': 'Potential authentication bypass attempt',
                'recommendation': 'Implement MFA, rate limiting, account lockout'
            },
            'security_misconfig': {
                'patterns': ['debug mode', 'stack trace', 'error details',
                            'exposed config', 'default credentials'],
                'severity': 'medium',
                'cwe': 'CWE-11',
                'description': 'Security misconfiguration detected',
                'recommendation': 'Disable debug mode, secure configurations'
            },
            'dos_attack': {
                'patterns': ['too many requests', 'rate limit', 'connection refused',
                            'memory exhausted', 'cpu maxed'],
                'severity': 'medium',
                'cwe': 'CWE-400',
                'description': 'Denial of Service indicator detected',
                'recommendation': 'Implement rate limiting, scale resources'
            },
            'open_redirect': {
                'patterns': ['redirect=', 'url=', 'next=', 'destination='],
                'severity': 'medium',
                'cwe': 'CWE-601',
                'description': 'Potential open redirect vulnerability',
                'recommendation': 'Validate redirect URLs, use allowlists'
            }
        }
        
        for vuln_type, details in vulnerability_patterns.items():
            if any(pattern in message for pattern in details['patterns']):
                vulnerabilities.append({
                    'type': vuln_type,
                    'severity': details['severity'],
                    'cwe': details['cwe'],
                    'description': details['description'],
                    'recommendation': details['recommendation'],
                    'confidence': 0.85
                })
        
        # Check for error logs that might indicate vulnerabilities
        if level in ['ERROR', 'CRITICAL'] and not vulnerabilities:
            vulnerabilities.append({
                'type': 'application_error',
                'severity': 'low',
                'cwe': 'CWE-755',
                'description': 'Application error detected - review for potential vulnerability',
                'recommendation': 'Investigate error details in logs',
                'confidence': 0.5
            })
        
        return {
            'vulnerabilities_detected': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities,
            'log_summary': {
                'level': level,
                'service': service,
                'message_preview': message[:200]
            }
        }
    
    def chat_with_security_assistant(self, user_message: str, context: Dict = None) -> Dict[str, Any]:
        """Chat with AI security assistant"""
        
        logger.info(f"Chat request - has_ai: {self.has_ai}, client: {type(self.client).__name__ if self.client else None}, provider: {self.provider}")
        
        # Check if AI is available
        if not self.has_ai or not self.client:
            logger.warning("AI not available - check API key configuration")
            return {
                'success': False,
                'response': '⚠️ AI is not configured. Please add GEMINI_API_KEY to your .env file. Get a free key at: https://makersuite.google.com/app/apikey',
                'mode': 'not_configured'
            }
        
        # Check rate limit
        if self.provider == 'gemini' and not self.rate_limiter.can_make_request():
            remaining = self.rate_limiter.get_remaining_requests()
            return {
                'success': False,
                'response': f'⚠️ Rate limit reached. You have {remaining} requests remaining this minute. Gemini free tier allows 15 requests per minute. Please wait a moment.',
                'mode': 'rate_limit',
                'remaining_requests': remaining
            }
        
        # Build system prompt with context
        system_prompt = """You are a Security Expert AI Assistant for a Log Monitoring and Security Detection Platform.
        
You help users with:
- Analyzing security threats and vulnerabilities
- Explaining security concepts in simple terms
- Recommending security best practices
- Helping investigate security incidents
- Answering questions about the platform's security features

Always provide helpful, accurate security guidance. If you're unsure about something, say so.
Keep responses concise but informative. Use bullet points when appropriate.
"""
        
        if context:
            # Add context about current system state
            context_info = f"""
Current System Status:
- Total Logs: {context.get('total_logs', 'N/A')}
- Active Alerts: {context.get('active_alerts', 'N/A')}
- Critical Alerts: {context.get('critical_alerts', 'N/A')}
- Recent Threats: {', '.join(context.get('recent_threats', [])) or 'None'}
"""
            system_prompt += context_info
        
        try:
            # Record request for rate limiting
            if self.provider == 'gemini':
                self.rate_limiter.add_request()
            
            if self.provider == 'openai':
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    temperature=0.7,
                    max_tokens=1000
                )
                result = response.choices[0].message.content
                return {
                    'success': True,
                    'response': result,
                    'mode': 'ai',
                    'remaining_requests': self.rate_limiter.get_remaining_requests() if self.provider == 'gemini' else None
                }
            
            elif self.provider == 'gemini':
                response = self.client.models.generate_content(
                    model=f'models/{self.model}',
                    contents=f"{system_prompt}\n\nUser: {user_message}"
                )
                return {
                    'success': True,
                    'response': response.text,
                    'mode': 'ai',
                    'remaining_requests': self.rate_limiter.get_remaining_requests()
                }
        
        except Exception as e:
            logger.error(f"AI chat failed: {e}", exc_info=True)
            error_msg = str(e)
            if 'quota' in error_msg.lower() or 'limit' in error_msg.lower():
                return {
                    'success': False,
                    'response': f'⚠️ API quota exceeded. The free tier has limits. Error: {error_msg}',
                    'mode': 'error'
                }
            return {
                'success': False,
                'response': f'⚠️ AI request failed: {error_msg}',
                'mode': 'error'
            }
        
        return {
            'success': False,
            'response': '⚠️ Unexpected error - AI provider not handled',
            'mode': 'error'
        }
    

    
    def _build_analysis_prompt(self, log_data: Dict[str, Any]) -> str:
        """Build analysis prompt from log data"""
        
        # Check if this is a Sysmon event
        event_id = log_data.get('event_id')
        event_type = log_data.get('event_type', '')
        
        if event_id or 'SYSMON' in event_type or 'sysmon' in str(log_data.get('channel', '')).lower():
            return self._build_sysmon_analysis_prompt(log_data)
        
        # Standard log analysis prompt
        return f"""Analyze this log entry for security threats:

Timestamp: {log_data.get('timestamp', 'N/A')}
Level: {log_data.get('level', 'N/A')}
Service: {log_data.get('service', 'N/A')}
IP Address: {log_data.get('ip_address', 'N/A')}
Message: {log_data.get('message', 'N/A')}

Return JSON with:
{{
    "threat_detected": true/false,
    "threat_type": "brute_force/suspicious_ip/repeated_errors/unusual_access/sql_injection/xss_attempt/ddos/other/null",
    "severity": "low/medium/high/critical or null",
    "confidence": 0.0-1.0,
    "description": "brief explanation",
    "recommendation": "recommended action"
}}
"""
    
    def _build_sysmon_analysis_prompt(self, log_data: Dict[str, Any]) -> str:
        """Build analysis prompt specifically for Windows Sysmon events"""
        
        event_id = log_data.get('event_id')
        event_type = log_data.get('event_type', 'Unknown')
        
        # Build detailed Sysmon context
        context = f"""Analyze this Windows Sysmon security event for threats:

=== EVENT INFORMATION ===
Event ID: {event_id}
Event Type: {event_type}
Channel: {log_data.get('channel', 'N/A')}
Provider: {log_data.get('provider_name', 'N/A')}
Computer: {log_data.get('computer', 'N/A')}
Timestamp: {log_data.get('timestamp', 'N/A')}
User: {log_data.get('user_name', 'N/A')}

=== PROCESS INFORMATION ===
Process Name: {log_data.get('process_name', 'N/A')}
Process Path: {log_data.get('process_path', 'N/A')}
Process ID: {log_data.get('process_id', 'N/A')}
Command Line: {log_data.get('process_command_line', 'N/A')}
Process Hash: {log_data.get('process_hash', 'N/A')}

=== PARENT PROCESS ===
Parent Process: {log_data.get('parent_process_name', 'N/A')}
Parent Path: {log_data.get('parent_process_path', 'N/A')}
Parent PID: {log_data.get('parent_process_id', 'N/A')}
Parent Command Line: {log_data.get('parent_command_line', 'N/A')}

=== NETWORK INFORMATION ===
Destination IP: {log_data.get('destination_ip', 'N/A')}
Destination Port: {log_data.get('destination_port', 'N/A')}
Source IP: {log_data.get('source_ip', 'N/A')}
Source Port: {log_data.get('source_port', 'N/A')}
Protocol: {log_data.get('protocol', 'N/A')}

=== REGISTRY/FILE/DNS ===
Registry Key: {log_data.get('registry_key', 'N/A')}
File Path: {log_data.get('file_path', 'N/A')}
DNS Query: {log_data.get('dns_query', 'N/A')}
DNS Result: {log_data.get('dns_result', 'N/A')}

=== RAW MESSAGE ===
{log_data.get('message', 'N/A')}

Analyze this Sysmon event for security threats. Consider:
1. Encoded/obfuscated commands (especially PowerShell)
2. Suspicious processes (mimikatz, metasploit, etc.)
3. Lateral movement indicators
4. Privilege escalation attempts
5. Persistence mechanisms
6. Data exfiltration attempts
7. Suspicious network connections

Return JSON with:
{{
    "threat_detected": true/false,
    "threat_type": "encoded_powershell/suspicious_process/lateral_movement/privilege_escalation/persistence/data_exfiltration/network_anomaly/other/null",
    "severity": "low/medium/high/critical or null",
    "confidence": 0.0-1.0,
    "description": "detailed explanation of findings",
    "recommendation": "recommended security response"
}}
"""
    
    def _parse_ai_response(self, response: str) -> Dict[str, Any]:
        """Parse AI response into structured format"""
        
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                result = json.loads(json_str)
                
                return {
                    'threat_detected': result.get('threat_detected', False),
                    'threat_type': result.get('threat_type'),
                    'severity': result.get('severity', 'low').lower(),
                    'confidence': result.get('confidence', 0.0),
                    'description': result.get('description', ''),
                    'recommendation': result.get('recommendation', '')
                }
        
        except (json.JSONDecodeError, AttributeError) as e:
            logger.warning(f"Failed to parse AI response: {e}")
        
        return self._generate_fallback_analysis({})
    
    def _parse_manual_response(self, response: str) -> Dict[str, Any]:
        """Parse manual analysis response"""
        
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                result = json.loads(json_str)
                
                return {
                    'threat_detected': result.get('threat_detected', False),
                    'threat_type': result.get('threat_type'),
                    'severity': result.get('severity', 'low').lower(),
                    'confidence': result.get('confidence', 0.0),
                    'description': result.get('description', response),
                    'recommendations': result.get('recommendations', '')
                }
        
        except (json.JSONDecodeError, AttributeError):
            pass
        
        return {
            'threat_detected': False,
            'threat_type': None,
            'severity': None,
            'confidence': 0.0,
            'description': response,
            'recommendations': ''
        }
    
    def _generate_fallback_analysis(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fallback analysis when AI is not available"""
        
        message = log_data.get('message', '').lower()
        level = log_data.get('level', '').upper()
        
        # Pattern-based threat detection
        if 'sql' in message and ('error' in message or 'syntax' in message):
            return {
                'threat_detected': True,
                'threat_type': 'sql_injection',
                'severity': 'high',
                'confidence': 0.7,
                'description': 'Possible SQL injection attempt detected',
                'recommendation': 'Review query and implement parameterized queries',
                'mode': 'pattern'
            }
        elif 'failed login' in message or 'authentication failed' in message:
            return {
                'threat_detected': True,
                'threat_type': 'brute_force',
                'severity': 'medium',
                'confidence': 0.6,
                'description': 'Failed authentication attempt detected',
                'recommendation': 'Monitor for repeated attempts from same IP',
                'mode': 'pattern'
            }
        elif level in ['ERROR', 'CRITICAL']:
            return {
                'threat_detected': False,
                'threat_type': None,
                'severity': 'low',
                'confidence': 0.5,
                'description': 'Error log detected - review for potential issues',
                'recommendation': 'Investigate error details',
                'mode': 'pattern'
            }
        
        return {
            'threat_detected': False,
            'threat_type': None,
            'severity': None,
            'confidence': 0.0,
            'description': 'No threats detected by pattern analysis',
            'recommendation': 'Continue monitoring',
            'mode': 'pattern'
        }
    
    def _generate_manual_fallback_analysis(self, log_text: str) -> Dict[str, Any]:
        """Generate fallback analysis for manual input when AI is not available"""
        
        log_lower = log_text.lower()
        
        # Pattern-based analysis
        if 'sql' in log_lower and ('error' in log_lower or 'injection' in log_lower):
            return {
                'threat_detected': True,
                'threat_type': 'sql_injection',
                'severity': 'high',
                'confidence': 0.7,
                'description': 'Possible SQL injection detected in log text',
                'recommendations': 'Use parameterized queries and input validation',
                'mode': 'pattern'
            }
        elif 'failed' in log_lower and 'login' in log_lower:
            return {
                'threat_detected': True,
                'threat_type': 'brute_force',
                'severity': 'medium',
                'confidence': 0.6,
                'description': 'Failed login attempt detected',
                'recommendations': 'Implement rate limiting and account lockout',
                'mode': 'pattern'
            }
        
        return {
            'threat_detected': False,
            'threat_type': None,
            'severity': None,
            'confidence': 0.0,
            'description': 'Pattern analysis complete. No obvious threats detected. For deeper analysis, configure Gemini API.',
            'recommendations': 'Add GEMINI_API_KEY to .env for AI-powered analysis',
            'mode': 'pattern'
        }


# Create new instance each time to get fresh settings
def get_ai_service() -> AIService:
    """Get a fresh AI service instance with latest settings"""
    return AIService()

