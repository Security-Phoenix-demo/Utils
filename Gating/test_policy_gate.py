#!/usr/bin/env python3
import json
import os
from policy_gating import PolicyGate, print_gate_results

def test_scenario(name: str, counts: dict, policy_file: str = None):
    """Run a test scenario and print results"""
    print(f"\n{'='*60}")
    print(f"Testing Scenario: {name}")
    print('='*60)
    
    gate = PolicyGate(policy_file)
    passed, details = gate.evaluate_gate(counts, f"Test Entity: {name}")
    print_gate_results(passed, details)
    return passed, details

def test_real_api_response():
    """Test with a real Phoenix API response data structure"""
    # Sample API response (similar to what we'd get from the Phoenix API)
    api_response = {
        "id": "019594da-6cfa-7b16-b55c-d44596b6d127",
        "organizationId": "1d542fab-e69e-4aca-8ab6-27ce204a0150",
        "name": "SPHX_Deployment",
        "criticality": 5,
        "value": None,
        "risk": 805,
        "riskMagnitude": 25920,
        "threshold": 400,
        "aboveThreshold": True,
        "type": "APPLICATION",
        "posture": {
            "findings": {
                "open": 36,
                "closed": 0,
                "openByRisk": {
                    "critical": 6,
                    "high": 18,
                    "medium": 12,
                    "low": 0,
                    "none": 0
                }
            },
            "assets": {
                "total": 6
            }
        },
        "default": False
    }
    
    # Extract vulnerability counts
    counts = api_response["posture"]["findings"]["openByRisk"]
    
    print(f"\n{'='*60}")
    print(f"TESTING WITH REAL API RESPONSE: {api_response['name']}")
    print('='*60)
    
    return test_scenario(
        f"API Response - {api_response['name']}",
        counts,
        "policy.json"
    )

def main():
    # Test scenarios
    scenarios = {
        "Production App (All under threshold)": {
            "critical": 2,
            "high": 15,
            "medium": 10,
            "low": 0,
            "none": 0
        },
        "Development App (Critical over threshold)": {
            "critical": 5,
            "high": 15,
            "medium": 10,
            "low": 0,
            "none": 0
        },
        "Legacy Component (Multiple violations)": {
            "critical": 4,
            "high": 20,
            "medium": 15,
            "low": 1,
            "none": 0
        },
        "New Component (At threshold limits)": {
            "critical": 3,
            "high": 18,
            "medium": 12,
            "low": 0,
            "none": 0
        },
        "Mobile App (Partial scan results)": {
            "critical": 2,
            "high": 15
        }
    }

    # Create test results array
    results = []
    
    # Test regular scenarios
    for name, counts in scenarios.items():
        passed, details = test_scenario(name, counts, "policy.json")
        results.append((name, passed, len([e for e in details["evaluations"] if not e["passed"]])))
    
    # Test with API response
    passed, details = test_real_api_response()
    results.append(("Real API Response", passed, len([e for e in details["evaluations"] if not e["passed"]])))

    # Final Summary
    print("\n" + "="*60)
    print("FINAL TEST SUMMARY")
    print("="*60)
    
    total_tests = len(results)
    passed_tests = sum(1 for _, passed, _ in results if passed)
    
    print(f"\nTotal Scenarios Tested: {total_tests}")
    print(f"Scenarios Passed: {passed_tests}")
    print(f"Scenarios Failed: {total_tests - passed_tests}")
    print("\nDetailed Results:")
    print("-----------------")
    
    for name, passed, failures in results:
        status = "✅ PASSED" if passed else f"❌ FAILED ({failures} violations)"
        print(f"{status} - {name}")
    
    # Additional gate failures explanation
    print("\nAdditional Explanation:")
    for name, passed, failures in results:
        if not passed:
            print(f"\n{name}:")
            if name == "Real API Response":
                print("  - Critical vulnerabilities: Actual 6, Threshold 3 (+3)")
                print("  - This is a mandatory gate that must pass")
            elif name == "Development App (Critical over threshold)":
                print("  - Critical vulnerabilities: Actual 5, Threshold 3 (+2)")
                print("  - This is a mandatory gate that must pass")
            elif name == "Legacy Component (Multiple violations)":
                print("  - Critical vulnerabilities: Actual 4, Threshold 3 (+1)")
                print("  - High vulnerabilities: Actual 20, Threshold 18 (+2)")
                print("  - Medium vulnerabilities: Actual 15, Threshold 12 (+3)")
                print("  - Low vulnerabilities: Actual 1, Threshold 0 (+1)")
                print("  - Critical is a mandatory gate that must pass")

if __name__ == "__main__":
    main() 