#!/usr/bin/env python3
import os
import sys
import json
import requests
from requests.auth import HTTPBasicAuth
from typing import Dict, Any, Tuple, List
import termcolor
import colorama

# Initialize colorama for cross-platform colored terminal output
colorama.init()

class PolicyGate:
    def __init__(self, policy_file: str = None):
        self.policy = self.load_policy(policy_file)
        
    def load_policy(self, policy_file: str = None) -> Dict[str, Any]:
        """Load policy from file or use default"""
        if policy_file and os.path.exists(policy_file):
            with open(policy_file, 'r') as f:
                return json.load(f)
        
        # Default policy if no file found
        return {
            "gates": [
                {"severity": "critical", "threshold": 3, "required": "must"},
                {"severity": "high", "threshold": 18, "required": "optional"},
                {"severity": "medium", "threshold": 12, "required": "optional"},
                {"severity": "low", "threshold": 0, "required": "optional"},
                {"severity": "none", "threshold": 0, "required": "optional"}
            ],
            "pass_logic": "ALL"
        }
    
    def evaluate_gate(self, vulnerability_counts: Dict[str, int], entity_name: str = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluate if the vulnerability counts pass the policy thresholds
        Returns: (passed, details)
        """
        results = {
            "overall_passed": True,
            "all_gates_passed": True,
            "must_gates_passed": True,
            "evaluations": [],
            "entity_name": entity_name,
            "policy": self.policy,
            "actual": vulnerability_counts
        }
        
        # Create severity lookup for faster access
        severity_map = {}
        for gate in self.policy["gates"]:
            severity_map[gate["severity"]] = gate
        
        # Evaluate each severity in vulnerability counts
        for severity, count in vulnerability_counts.items():
            if severity in severity_map:
                gate = severity_map[severity]
                evaluation = self._evaluate_single_gate(severity, count, gate)
                results["evaluations"].append(evaluation)
                
                # Update pass status
                if not evaluation["passed"]:
                    results["all_gates_passed"] = False
                    if gate["required"] == "must":
                        results["must_gates_passed"] = False
        
        # Add any gates that weren't in vulnerability counts
        for gate in self.policy["gates"]:
            if gate["severity"] not in vulnerability_counts:
                count = 0  # Default count for missing severities
                evaluation = self._evaluate_single_gate(gate["severity"], count, gate)
                results["evaluations"].append(evaluation)
                
                # Also check these gates for pass status
                if not evaluation["passed"]:
                    results["all_gates_passed"] = False
                    if gate["required"] == "must":
                        results["must_gates_passed"] = False
        
        # Sort evaluations by severity order
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
        results["evaluations"].sort(key=lambda x: severity_order.get(x["severity"], 999))
        
        # Determine final pass/fail based on policy logic
        pass_logic = self.policy.get("pass_logic", "ALL").upper()
        if pass_logic == "ALL":
            results["overall_passed"] = results["all_gates_passed"]
        elif pass_logic == "REQUIRED":
            results["overall_passed"] = results["must_gates_passed"]  # Only required gates matter
        else:
            results["overall_passed"] = results["must_gates_passed"]  # Default to REQUIRED logic
            
        return results["overall_passed"], results
    
    def _evaluate_single_gate(self, severity: str, count: int, gate: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a single severity gate"""
        threshold = gate["threshold"]
        required = gate["required"]
        
        difference = threshold - count
        
        evaluation = {
            "severity": severity,
            "threshold": threshold,
            "actual": count,
            "difference": difference,
            "required": required,
            "passed": count <= threshold,
            "comparison": "="  # Default comparison
        }
        
        # Set comparison indicator
        if difference > 0:
            evaluation["comparison"] = "-" + str(difference)
        elif difference < 0:
            evaluation["comparison"] = "+" + str(abs(difference))
        else:
            evaluation["comparison"] = "="
            
        return evaluation

def get_access_token(client_id, client_secret, base_url="https://api.demo.appsecphx.io"):
    """Get Phoenix access token"""
    if not client_id:
        client_id = input("Enter your Phoenix Client ID (CLIENT_ID): ").strip()
        os.environ["CLIENT_ID"] = client_id
    if not client_secret:
        client_secret = input("Enter your Phoenix Client Secret (CLIENT_SECRET): ").strip()
        os.environ["CLIENT_SECRET"] = client_secret

    if not client_id or not client_secret:
        print("Error: Missing Phoenix client_id or client_secret.")
        return None

    url = f"{base_url}/v1/auth/access_token"
    print(f"Requesting Phoenix token from: {url}")

    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        return response.json().get('token')
    else:
        print(f"Failed to obtain token: HTTP {response.status_code}")
        print("Response:", response.text)
    return None

def get_vulnerability_counts(entity_type: str, name: str, app_name: str, token: str, base_url: str) -> Dict[str, int]:
    """Get vulnerability counts from Phoenix"""
    if entity_type not in ['application', 'component']:
        raise ValueError("entity_type must be 'application' or 'component'")
    
    endpoint = f"{base_url}/v1/{entity_type}s/posture"
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    if entity_type == 'application':
        payload = {
            'applicationSelector': {'name': name},
            'excludeRiskAccepted': True  # Always exclude risk-accepted vulnerabilities
        }
    else:
        payload = {
            'selector': {
                'applicationSelector': {'name': app_name},
                'componentSelector': {'name': name}
            },
            'excludeRiskAccepted': True  # Always exclude risk-accepted vulnerabilities
        }

    print(f"\nSending request to: {endpoint}")
    print(f"Request payload: {json.dumps(payload, indent=2)}")
    
    response = requests.post(endpoint, headers=headers, json=payload)
    
    if response.status_code not in [200, 201]:
        print(f"Error fetching data: HTTP {response.status_code}")
        try:
            print("Error details:", json.dumps(response.json(), indent=2))
        except:
            print("Response text:", response.text)
        return None
        
    data = response.json()
    
    # Handle standard Phoenix API response format
    if "posture" in data and "findings" in data["posture"] and "openByRisk" in data["posture"]["findings"]:
        return data["posture"]["findings"]["openByRisk"]
    
    # Fallback to vulnerabilityCounts
    return data.get('vulnerabilityCounts', {})

def print_gate_results(passed: bool, details: Dict[str, Any]):
    """Print formatted gate results with colored output"""
    entity_name = details.get('entity_name', 'Unknown')
    
    print(f"\n{'='*60}")
    print(f"GATE EVALUATION RESULTS - {entity_name}")
    print(f"{'='*60}")
    
    # Print overall gate status with color
    status_color = "green" if passed else "red"
    overall_status = "PASSED" if passed else "FAILED"
    status_text = termcolor.colored(f"Overall Gate Status: {overall_status}", status_color, attrs=["bold"])
    print(status_text)
    
    # Print pass logic
    policy = details.get("policy", {})
    pass_logic = policy.get("pass_logic", "ALL")
    if pass_logic == "REQUIRED":
        print(f"Pass Logic: {pass_logic} (Only required gates must pass, optional gates may fail)")
    else:
        print(f"Pass Logic: {pass_logic} (All gates must pass)")
    
    print(f"\n{'='*60}")
    print("POLICY EVALUATION BY SEVERITY")
    print(f"{'='*60}")
    
    # Create a table-like format with color
    header = f"{'SEVERITY':<10} {'THRESHOLD':<10} {'ACTUAL':<10} {'COMPARISON':<15} {'REQUIRED':<10} {'STATUS':<10}"
    print(termcolor.colored(header, attrs=["bold"]))
    print("-" * 60)
    
    for eval in details["evaluations"]:
        severity = eval["severity"].upper()
        threshold = str(eval["threshold"])
        actual = str(eval["actual"])
        comparison = eval["comparison"]
        required = eval["required"].upper()
        status = "PASS" if eval["passed"] else "FAIL"
        
        # Mark optional gate failures differently when using REQUIRED pass logic
        is_optional_failure = (not eval["passed"] and eval["required"] != "must" and 
                              policy.get("pass_logic", "ALL") == "REQUIRED")
        
        # Color-code comparison
        if comparison == "=":
            comp_colored = termcolor.colored(comparison, "yellow", attrs=["bold"])
        elif comparison.startswith("-"):
            comp_colored = termcolor.colored(comparison, "green", attrs=["bold"])
        else:  # starts with +
            comp_colored = termcolor.colored(comparison, "red", attrs=["bold"])
        
        # Color-code the status
        if is_optional_failure:
            # Optional gate failure with REQUIRED pass logic - use yellow to show it doesn't affect overall status
            status_colored = termcolor.colored(f"{status}*", "yellow", attrs=["bold"])
        else:
            status_colored = termcolor.colored(status, "green" if eval["passed"] else "red", attrs=["bold"])
        
        # Create the row with colored elements
        row = f"{severity:<10} {threshold:<10} {actual:<10} {comp_colored:<15} {required:<10} {status_colored:<10}"
        print(row)
    
    # Add a legend for optional gate failures if needed and REQUIRED logic is used
    has_optional_failures = any(not e["passed"] and e["required"] != "must" 
                               for e in details["evaluations"])
    if has_optional_failures and policy.get("pass_logic", "ALL") == "REQUIRED":
        print("\n* Optional gate failures don't affect overall status with REQUIRED pass logic")
    
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    
    # Count overall statistics
    total_gates = len(details["evaluations"])
    passed_gates = sum(1 for e in details["evaluations"] if e["passed"])
    failed_gates = total_gates - passed_gates
    must_gates = sum(1 for e in details["evaluations"] if e["required"] == "must")
    failed_must_gates = sum(1 for e in details["evaluations"] if e["required"] == "must" and not e["passed"])
    optional_gates = total_gates - must_gates
    failed_optional_gates = failed_gates - failed_must_gates
    
    print(f"Total Gates Checked: {total_gates}")
    print(f"Total Passed: {passed_gates}")
    print(f"Total Failed: {failed_gates}")
    print(f"Required Gates: {must_gates}")
    print(f"Failed Required Gates: {failed_must_gates}")
    print(f"Optional Gates: {optional_gates}")
    print(f"Failed Optional Gates: {failed_optional_gates}")
    
    # Final decision explanation
    print(f"\n{'='*60}")
    print("GATE DECISION EXPLANATION")
    print(f"{'='*60}")
    
    if pass_logic == "ALL":
        if passed:
            print(termcolor.colored("✅ PASS: All gates have passed.", "green", attrs=["bold"]))
        else:
            print(termcolor.colored("❌ FAIL: Not all gates have passed.", "red", attrs=["bold"]))
            
            # List the failures
            print("\nFailed Gates:")
            for eval in details["evaluations"]:
                if not eval["passed"]:
                    severity = eval["severity"].upper()
                    msg = f"- {severity}: Threshold {eval['threshold']}, Actual {eval['actual']} ({eval['comparison']})"
                    if eval["required"] == "must":
                        msg += " (Required Gate)"
                    print(msg)
    else:  # REQUIRED logic
        if passed:
            print(termcolor.colored("✅ PASS: All required gates have passed.", "green", attrs=["bold"]))
            # Show optional gate failures if any
            failed_optional = [e for e in details["evaluations"] if not e["passed"] and e["required"] != "must"]
            if failed_optional:
                print("\nNote: The following optional gates failed but do not affect the overall status:")
                for eval in failed_optional:
                    severity = eval["severity"].upper()
                    print(f"- {severity}: Threshold {eval['threshold']}, Actual {eval['actual']} ({eval['comparison']})")
        else:
            print(termcolor.colored("❌ FAIL: One or more required gates have failed.", "red", attrs=["bold"]))
            
            # List the failures
            print("\nFailed Required Gates:")
            for eval in details["evaluations"]:
                if not eval["passed"] and eval["required"] == "must":
                    severity = eval["severity"].upper()
                    print(f"- {severity}: Threshold {eval['threshold']}, Actual {eval['actual']} ({eval['comparison']})")

def main():
    # Configuration
    base_url = "https://api.poc1.appsecphx.io"
    client_id = os.environ.get("CLIENT_ID", "")
    client_secret = os.environ.get("CLIENT_SECRET", "")
    
    # Initialize policy gate
    policy_file = "policy.json" if os.path.exists("policy.json") else None
    gate = PolicyGate(policy_file)
    
    # Get query type
    while True:
        choice = input("What would you like to evaluate? (1: Application, 2: Component): ").strip()
        if choice in ['1', '2']:
            break
        print("Invalid choice. Please enter 1 for Application or 2 for Component.")
    
    entity_type = 'application' if choice == '1' else 'component'
    
    # Get entity details
    if entity_type == 'component':
        name = input("Enter the component name: ").strip()
        app_name = input("Enter the application name containing this component: ").strip()
        entity_name = f"Component: {name} (Application: {app_name})"
    else:
        name = input("Enter the application name: ").strip()
        app_name = name
        entity_name = f"Application: {name}"
    
    # Get token and fetch data
    token = get_access_token(client_id, client_secret, base_url)
    if not token:
        return
    
    counts = get_vulnerability_counts(entity_type, name, app_name, token, base_url)
    if not counts:
        return
    
    # Evaluate gate
    passed, details = gate.evaluate_gate(counts, entity_name)
    
    # Print results
    print_gate_results(passed, details)

if __name__ == "__main__":
    main() 