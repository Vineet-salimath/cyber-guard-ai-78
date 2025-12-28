"""
TEST SUITE FOR REAL-TIME THREAT DETECTION
Comprehensive tests to verify the real-time detection system
"""

import unittest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(__file__))

from real_time_threat_detector import (
    RealTimeThreatDetector, 
    ThreatDetectorConfig,
    create_detector
)
from integration_realtime import scan_url_realtime, convert_to_flask_response


class TestRealTimeThreatDetector(unittest.TestCase):
    """Test real-time threat detection"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = ThreatDetectorConfig()
        self.config.VIRUSTOTAL_API_KEY = "test_vt_key"
        self.config.GOOGLE_SAFE_BROWSING_API_KEY = "test_gsb_key"
        self.config.IPQUALITYSCORE_API_KEY = "test_ipqs_key"
        self.detector = RealTimeThreatDetector(self.config)
    
    def test_valid_url_validation(self):
        """Test URL validation with valid URLs"""
        valid_urls = [
            "https://www.google.com",
            "http://example.com",
            "https://example.co.uk/path?query=value"
        ]
        
        for url in valid_urls:
            self.assertTrue(self.detector._is_valid_url(url))
    
    def test_invalid_url_validation(self):
        """Test URL validation with invalid URLs"""
        invalid_urls = [
            "not a url",
            "example.com",  # No protocol
            "ftp://example.com",  # Unsupported protocol
            ""
        ]
        
        for url in invalid_urls:
            self.assertFalse(self.detector._is_valid_url(url))
    
    def test_caching_mechanism(self):
        """Test result caching"""
        test_url = "https://example.com"
        mock_result = {
            'url': test_url,
            'threat_level': 'SAFE',
            'overall_risk_score': 0
        }
        
        # Cache the result
        self.detector._cache_result(test_url, mock_result)
        
        # Retrieve from cache
        cached = self.detector._get_cached_result(test_url)
        self.assertIsNotNone(cached)
        self.assertEqual(cached['threat_level'], 'SAFE')
    
    def test_cache_expiration(self):
        """Test cache TTL expiration"""
        test_url = "https://example.com"
        mock_result = {'url': test_url, 'threat_level': 'SAFE'}
        
        # Set very short TTL
        self.detector.config.CACHE_TTL = 0.001
        
        # Cache the result
        self.detector._cache_result(test_url, mock_result)
        
        # Wait for expiration
        import time
        time.sleep(0.1)
        
        # Should return None (expired)
        cached = self.detector._get_cached_result(test_url)
        self.assertIsNone(cached)
    
    def test_error_response_format(self):
        """Test error response format"""
        url = "invalid-url"
        error_msg = "Invalid URL format"
        
        response = self.detector._error_response(url, error_msg)
        
        self.assertIn('url', response)
        self.assertIn('timestamp', response)
        self.assertIn('error', response)
        self.assertIn('success', response)
        self.assertFalse(response['success'])
        self.assertEqual(response['error'], error_msg)
    
    @patch('requests.post')
    def test_virustotal_check_success(self, mock_post):
        """Test successful VirusTotal API check"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'id': 'test-id-123',
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 5,
                        'suspicious': 2,
                        'harmless': 80,
                        'undetected': 3
                    }
                }
            }
        }
        mock_post.return_value = mock_response
        
        result = self.detector._check_virustotal("https://example.com")
        
        self.assertTrue(result.get('success'))
        self.assertEqual(result['malicious'], 5)
        self.assertEqual(result['suspicious'], 2)
    
    @patch('requests.get')
    def test_safebrowsing_check_safe(self, mock_get):
        """Test Google Safe Browsing - SAFE response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'matches': []}
        mock_get.return_value = mock_response
        
        result = self.detector._check_safebrowsing("https://google.com")
        
        self.assertTrue(result.get('success'))
        self.assertFalse(result.get('malicious'))
        self.assertEqual(result['risk_score'], 0)
    
    @patch('requests.get')
    def test_safebrowsing_check_malicious(self, mock_get):
        """Test Google Safe Browsing - MALICIOUS response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'matches': [
                {'threatType': 'MALWARE'},
                {'threatType': 'SOCIAL_ENGINEERING'}
            ]
        }
        mock_get.return_value = mock_response
        
        result = self.detector._check_safebrowsing("https://malicious-site.tk")
        
        self.assertTrue(result.get('success'))
        self.assertTrue(result.get('malicious'))
        self.assertEqual(result['risk_score'], 95)
    
    @patch('requests.get')
    def test_ipqualityscore_check(self, mock_get):
        """Test IPQualityScore API check"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'fraud_score': 45.5,
            'suspicious': True,
            'threat_types': ['phishing']
        }
        mock_get.return_value = mock_response
        
        result = self.detector._check_ipqualityscore("https://suspicious-site.com")
        
        self.assertTrue(result.get('success'))
        self.assertEqual(result['fraud_score'], 45.5)
        self.assertTrue(result['suspicious'])
    
    def test_result_aggregation_all_safe(self):
        """Test result aggregation when all APIs report SAFE"""
        api_results = {
            'virustotal': {
                'success': True,
                'malicious': 0,
                'risk_score': 0
            },
            'safebrowsing': {
                'success': True,
                'malicious': False,
                'risk_score': 0
            },
            'ipqualityscore': {
                'success': True,
                'malicious': False,
                'risk_score': 5
            }
        }
        
        result = self.detector._aggregate_results("https://google.com", api_results)
        
        self.assertEqual(result['threat_level'], 'SAFE')
        self.assertLess(result['overall_risk_score'], 40)
    
    def test_result_aggregation_malicious(self):
        """Test result aggregation with multiple malicious votes"""
        api_results = {
            'virustotal': {
                'success': True,
                'malicious': 10,
                'risk_score': 85
            },
            'safebrowsing': {
                'success': True,
                'malicious': True,
                'risk_score': 95
            },
            'ipqualityscore': {
                'success': True,
                'malicious': True,
                'risk_score': 82
            }
        }
        
        result = self.detector._aggregate_results("https://malicious.tk", api_results)
        
        self.assertEqual(result['threat_level'], 'MALICIOUS')
        self.assertGreater(result['overall_risk_score'], 70)
    
    def test_result_aggregation_suspicious(self):
        """Test result aggregation with single malicious vote"""
        api_results = {
            'virustotal': {
                'success': True,
                'malicious': 0,
                'risk_score': 10
            },
            'safebrowsing': {
                'success': True,
                'malicious': True,
                'risk_score': 95
            },
            'ipqualityscore': {
                'success': True,
                'malicious': False,
                'risk_score': 15
            }
        }
        
        result = self.detector._aggregate_results("https://suspicious.com", api_results)
        
        self.assertEqual(result['threat_level'], 'SUSPICIOUS')


class TestIntegration(unittest.TestCase):
    """Test integration module"""
    
    @patch('integration_realtime.get_detector')
    def test_flask_response_conversion_safe(self, mock_detector):
        """Test Flask response conversion for SAFE URL"""
        detection_result = {
            'url': 'https://google.com',
            'threat_level': 'SAFE',
            'overall_risk_score': 0,
            'timestamp': datetime.now().isoformat(),
            'confidence': 100,
            'findings': [],
            'votes': {'safe': 3},
            'api_results': {
                'virustotal': {
                    'success': True,
                    'malicious': 0,
                    'suspicious': 0
                },
                'safebrowsing': {
                    'success': True,
                    'malicious': False
                },
                'ipqualityscore': {
                    'success': True,
                    'malicious': False
                }
            }
        }
        
        response = convert_to_flask_response(detection_result)
        
        self.assertEqual(response['threat_level'], 'SAFE')
        self.assertEqual(response['overall_risk_score'], 0)
        self.assertEqual(response['stats']['malicious'], 0)
    
    @patch('integration_realtime.get_detector')
    def test_flask_response_conversion_malicious(self, mock_detector):
        """Test Flask response conversion for MALICIOUS URL"""
        detection_result = {
            'url': 'https://malicious.tk',
            'threat_level': 'MALICIOUS',
            'overall_risk_score': 92,
            'timestamp': datetime.now().isoformat(),
            'confidence': 100,
            'findings': ['VirusTotal: 15 threats', 'Google: Malware'],
            'votes': {'malicious': 2},
            'api_results': {
                'virustotal': {
                    'success': True,
                    'malicious': 15,
                    'suspicious': 5,
                    'harmless': 70
                },
                'safebrowsing': {
                    'success': True,
                    'malicious': True
                },
                'ipqualityscore': {
                    'success': True,
                    'malicious': True,
                    'fraud_score': 85
                }
            }
        }
        
        response = convert_to_flask_response(detection_result)
        
        self.assertEqual(response['threat_level'], 'MALICIOUS')
        self.assertGreater(response['overall_risk_score'], 70)
        self.assertEqual(response['stats']['malicious'], 15)


class TestErrorHandling(unittest.TestCase):
    """Test error handling scenarios"""
    
    def setUp(self):
        self.config = ThreatDetectorConfig()
        self.detector = RealTimeThreatDetector(self.config)
    
    @patch('requests.post')
    def test_api_timeout_handling(self, mock_post):
        """Test handling of API timeout"""
        from requests.exceptions import Timeout
        mock_post.side_effect = Timeout()
        
        result = self.detector._check_virustotal("https://example.com")
        
        self.assertFalse(result.get('success'))
        self.assertIn('error', result)
    
    @patch('requests.get')
    def test_api_connection_error(self, mock_get):
        """Test handling of connection errors"""
        from requests.exceptions import ConnectionError
        mock_get.side_effect = ConnectionError()
        
        result = self.detector._check_safebrowsing("https://example.com")
        
        self.assertFalse(result.get('success'))
        self.assertIn('error', result)
    
    def test_partial_api_failure(self):
        """Test system works when some APIs fail"""
        api_results = {
            'virustotal': {
                'success': False,
                'error': 'API timeout'
            },
            'safebrowsing': {
                'success': True,
                'malicious': False,
                'risk_score': 0
            },
            'ipqualityscore': {
                'success': True,
                'malicious': False,
                'risk_score': 5
            }
        }
        
        result = self.detector._aggregate_results("https://example.com", api_results)
        
        # Should still return a result
        self.assertIn('threat_level', result)
        self.assertIsNotNone(result['threat_level'])


class TestPerformance(unittest.TestCase):
    """Test performance characteristics"""
    
    def setUp(self):
        self.config = ThreatDetectorConfig()
        self.detector = RealTimeThreatDetector(self.config)
    
    def test_caching_improves_performance(self):
        """Test that caching significantly improves performance"""
        import time
        
        test_url = "https://example.com"
        mock_result = {
            'url': test_url,
            'threat_level': 'SAFE',
            'overall_risk_score': 0
        }
        
        # Cache the result
        self.detector._cache_result(test_url, mock_result)
        
        # First retrieval (cached)
        start = time.time()
        for _ in range(1000):
            self.detector._get_cached_result(test_url)
        cached_time = time.time() - start
        
        # Should be very fast (< 10ms for 1000 retrieves)
        self.assertLess(cached_time, 0.01)
    
    def test_url_validation_performance(self):
        """Test URL validation performance"""
        import time
        
        test_urls = [
            "https://www.google.com",
            "https://example.com/path?query=value",
            "http://localhost:5000"
        ]
        
        start = time.time()
        for _ in range(10000):
            for url in test_urls:
                self.detector._is_valid_url(url)
        elapsed = time.time() - start
        
        # Should validate 10k URLs in < 100ms
        self.assertLess(elapsed, 0.1)


class TestConfiguration(unittest.TestCase):
    """Test configuration handling"""
    
    def test_detector_creation_with_keys(self):
        """Test detector creation with API keys"""
        detector = create_detector(
            virustotal_key="vt_test_key",
            safebrowsing_key="gsb_test_key",
            ipqs_key="ipqs_test_key"
        )
        
        self.assertIsNotNone(detector)
        self.assertEqual(detector.config.VIRUSTOTAL_API_KEY, "vt_test_key")
        self.assertEqual(detector.config.GOOGLE_SAFE_BROWSING_API_KEY, "gsb_test_key")
        self.assertEqual(detector.config.IPQUALITYSCORE_API_KEY, "ipqs_test_key")
    
    def test_detector_creation_without_keys(self):
        """Test detector creation without API keys (graceful degradation)"""
        detector = create_detector()
        
        self.assertIsNotNone(detector)
        self.assertIsNone(detector.config.VIRUSTOTAL_API_KEY)


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestRealTimeThreatDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestErrorHandling))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformance))
    suite.addTests(loader.loadTestsFromTestCase(TestConfiguration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
