#!/usr/bin/env python3
"""
Debug: Trace layer scores for a suspicious URL
"""

from risk_engine import UnifiedRiskEngine

engine = UnifiedRiskEngine()
url = "http://paypal-update-info-support.com/login/secure"

result = engine.analyze(url, {})

print("\n" + "="*80)
print("LAYER SCORE ANALYSIS")
print("="*80)
print(f"URL: {url}\n")

print("Layer Scores:")
for layer, score in result['layer_scores'].items():
    print(f"  {layer}: {score}")

print(f"\nDetailed Analysis:")
for layer_name, layer_data in result['detailed_analysis'].items():
    print(f"\n{layer_name.upper()}:")
    print(f"  Risk Score: {layer_data.get('risk_score', layer_data.get('signature_score', layer_data.get('ml_confidence', layer_data.get('heuristic_score', 0))))} ")
    if 'findings' in layer_data:
        for finding in layer_data.get('findings', [])[:3]:
            print(f"    - {finding}")

print(f"\n{'='*80}")
print(f"Overall Risk: {result['overall_risk']}/100")
print(f"Classification: {result['final_classification']}")
print(f"{'='*80}\n")
