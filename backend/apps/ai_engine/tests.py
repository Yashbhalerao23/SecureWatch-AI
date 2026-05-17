"""
AI Engine Tests
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from apps.ai_engine.ai_service import AIService
from apps.logs.models import Log
from apps.alerts.models import Alert

User = get_user_model()


class AIServiceTestCase(TestCase):
    """Test AI Service functionality"""
    
    def setUp(self):
        self.ai_service = AIService()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            role='admin'
        )
    
    def test_ai_service_initialization(self):
        """Test AI service initializes correctly"""
        self.assertIsNotNone(self.ai_service)
        self.assertEqual(self.ai_service.provider, 'gemini')
        self.assertTrue(self.ai_service.enabled)
    
    def test_pattern_based_sql_injection_detection(self):
        """Test pattern-based SQL injection detection"""
        log_text = "ERROR: SQL syntax error - SELECT * FROM users WHERE id='1' OR '1'='1'"
        result = self.ai_service._generate_manual_fallback_analysis(log_text)
        
        self.assertTrue(result['threat_detected'])
        self.assertEqual(result['threat_type'], 'sql_injection')
        self.assertEqual(result['severity'], 'high')
    
    def test_pattern_based_brute_force_detection(self):
        """Test pattern-based brute force detection"""
        log_text = "2024-01-15 10:30:45 ERROR Failed login attempt from 192.168.1.100"
        result = self.ai_service._generate_manual_fallback_analysis(log_text)
        
        self.assertTrue(result['threat_detected'])
        self.assertEqual(result['threat_type'], 'brute_force')
    
    def test_vulnerability_detection(self):
        """Test vulnerability detection in logs"""
        log_data = {
            'message': 'SQL injection attempt detected',
            'level': 'ERROR',
            'service': 'web-app'
        }
        
        result = self.ai_service.detect_vulnerabilities(log_data)
        
        self.assertTrue(result['vulnerabilities_detected'])
        self.assertGreater(len(result['vulnerabilities']), 0)
        self.assertEqual(result['vulnerabilities'][0]['type'], 'sql_injection')
    
    def test_rate_limiter(self):
        """Test rate limiter functionality"""
        limiter = self.ai_service.rate_limiter
        
        # Should allow requests initially
        self.assertTrue(limiter.can_make_request())
        
        # Record a request
        limiter.add_request()
        remaining = limiter.get_remaining_requests()
        
        self.assertLess(remaining, 15)
        self.assertGreaterEqual(remaining, 0)
    
    def test_ai_analysis_with_valid_api_key(self):
        """Test AI analysis when API key is configured"""
        if not self.ai_service.has_ai:
            self.skipTest("AI not configured - skipping")
        
        log_text = "ERROR: Failed login attempt from 192.168.1.100"
        result = self.ai_service.analyze_manual(log_text)
        
        self.assertIn('threat_detected', result)
        self.assertIn('confidence', result)
        self.assertIn('description', result)
    
    def test_fallback_when_ai_unavailable(self):
        """Test fallback to pattern matching when AI unavailable"""
        # Temporarily disable AI
        original_has_ai = self.ai_service.has_ai
        self.ai_service.has_ai = False
        
        log_text = "ERROR: SQL injection detected"
        result = self.ai_service.analyze_manual(log_text)
        
        self.assertEqual(result['mode'], 'pattern')
        self.assertTrue(result['threat_detected'])
        
        # Restore
        self.ai_service.has_ai = original_has_ai


class AIAnalysisViewTestCase(TestCase):
    """Test AI Analysis views"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            role='analyst'
        )
        self.client.login(username='testuser', password='testpass123')
    
    def test_ai_analysis_page_loads(self):
        """Test AI analysis page loads correctly"""
        response = self.client.get('/ai-analysis/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'AI Log Analysis')
    
    def test_ai_analysis_submission(self):
        """Test submitting log for AI analysis"""
        log_text = "ERROR: Failed login from 192.168.1.100"
        
        response = self.client.post('/ai-analysis/result/', {
            'log_text': log_text
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Analysis Results')
    
    def test_ai_analysis_requires_login(self):
        """Test AI analysis requires authentication"""
        self.client.logout()
        
        response = self.client.get('/ai-analysis/')
        
        self.assertEqual(response.status_code, 302)  # Redirect to login


class AIAPITestCase(TestCase):
    """Test AI API endpoints"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='apiuser',
            password='testpass123',
            role='analyst'
        )
    
    def test_analyze_api_endpoint(self):
        """Test AI analysis API endpoint"""
        self.client.login(username='apiuser', password='testpass123')
        
        response = self.client.post('/api/v1/ai/analyze/', {
            'log_text': 'ERROR: SQL injection attempt'
        }, content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('threat_detected', data)
    
    def test_api_requires_authentication(self):
        """Test API requires authentication"""
        response = self.client.post('/api/v1/ai/analyze/', {
            'log_text': 'test'
        }, content_type='application/json')
        
        self.assertEqual(response.status_code, 302)  # Redirect to login
