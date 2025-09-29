#!/usr/bin/env python3
"""
Simple test runner for TerraSafe demonstrations
"""

import sys
from pathlib import Path
from security_scanner import IntelligentSecurityScanner, format_results


def test_all_files():
    """Test all three configurations"""
    scanner = IntelligentSecurityScanner()
    
    test_cases = [
        ("test_files/vulnerable.tf", "HIGH RISK - Multiple critical issues"),
        ("test_files/secure.tf", "LOW RISK - Best practices followed"),
        ("test_files/mixed.tf", "MEDIUM RISK - Some improvements needed")
    ]
    
    print("\n" + "="*70)
    print("TERRASAFE - SECURITY SCANNER DEMONSTRATION")
    print("="*70)
    
    for filepath, expected in test_cases:
        if Path(filepath).exists():
            print(f"\n🔍 Testing: {filepath}")
            print(f"   Expected: {expected}")
            
            results = scanner.scan(filepath)
            score = results['score']
            
            # Validate score ranges
            if "vulnerable" in filepath:
                assert score > 70, f"Vulnerable file should score >70, got {score}"
                print(f"   ✅ Score: {score}/100 (CRITICAL as expected)")
            elif "secure" in filepath:
                assert score < 30, f"Secure file should score <30, got {score}"
                print(f"   ✅ Score: {score}/100 (SECURE as expected)")
            elif "mixed" in filepath:
                assert 30 <= score <= 70, f"Mixed file should score 30-70, got {score}"
                print(f"   ✅ Score: {score}/100 (MEDIUM as expected)")
            
            # Print vulnerability count
            vulns = results['summary']
            total = sum(vulns.values())
            print(f"   📊 Issues found: {total}")
            if vulns['critical'] > 0:
                print(f"      - Critical: {vulns['critical']}")
            if vulns['high'] > 0:
                print(f"      - High: {vulns['high']}")
            if vulns['medium'] > 0:
                print(f"      - Medium: {vulns['medium']}")
    
    print("\n" + "="*70)
    print("✅ All tests passed! Scanner working correctly.")
    print("="*70)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Test specific file
        scanner = IntelligentSecurityScanner()
        results = scanner.scan(sys.argv[1])
        print(format_results(results))
    else:
        # Run all tests
        test_all_files()