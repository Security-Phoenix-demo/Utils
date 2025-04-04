#!/usr/bin/env python3
import os
import sys
import json
import yaml
import requests
from requests.auth import HTTPBasicAuth
from typing import Dict, Any, Tuple, List, Optional
import termcolor
import colorama
import traceback

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
            "pass_logic": "REQUIRED"
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
        pass_logic = self.policy.get("pass_logic", "REQUIRED").upper()
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

def get_access_token() -> str:
    """Get Phoenix access token from environment variables"""
    client_id = os.environ.get("PHOENIX_CLIENT_ID", "")
    client_secret = os.environ.get("PHOENIX_CLIENT_SECRET", "")
    base_url = os.environ.get("PHOENIX_API_URL", "https://api.poc1.appsecphx.io")
    
    if not client_id or not client_secret:
        print("Error: Missing environment variables PHOENIX_CLIENT_ID or PHOENIX_CLIENT_SECRET.")
        sys.exit(1)

    url = f"{base_url}/v1/auth/access_token"
    print(f"Requesting Phoenix token from: {url}")

    try:
        response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
        response.raise_for_status()
        return response.json().get('token')
    except Exception as e:
        print(f"Failed to obtain Phoenix token: {str(e)}")
        if isinstance(e, requests.exceptions.HTTPError):
            print(f"Response status: {response.status_code}, Response: {response.text}")
        sys.exit(1)

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
    
    try:
        response = requests.post(endpoint, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        
        # Handle standard Phoenix API response format
        if "posture" in data and "findings" in data["posture"] and "openByRisk" in data["posture"]["findings"]:
            return data["posture"]["findings"]["openByRisk"]
        
        # Fallback to vulnerabilityCounts
        return data.get('vulnerabilityCounts', {})
    except Exception as e:
        print(f"Error fetching vulnerability data: {str(e)}")
        if isinstance(e, requests.exceptions.HTTPError):
            print(f"Response status: {response.status_code}, Response: {response.text}")
        sys.exit(1)

class CoreStructureParser:
    """Parser for different core-structure file formats"""
    
    @staticmethod
    def parse(file_path: str) -> List[Dict[str, Any]]:
        """
        Parse the core-structure file and return a list of application and component pairs
        Returns: List of dicts containing app_name and component_name (optional)
        """
        if not os.path.exists(file_path):
            print(f"Warning: core-structure file not found at {file_path}")
            return []
            
        # Try to determine the file format
        with open(file_path, 'r') as f:
            content = f.read().strip()
            
        # Check if it's YAML format
        if content.startswith('DeploymentGroups:') or content.startswith('---'):
            return CoreStructureParser._parse_yaml(content, file_path)
        else:
            # Default to simple format (application: X, component: Y)
            return CoreStructureParser._parse_simple(content)
    
    @staticmethod
    def _parse_simple(content: str) -> List[Dict[str, Any]]:
        """Parse simple format with application: X, component: Y"""
        lines = content.split('\n')
        app_name = None
        component_name = None
        
        for line in lines:
            line = line.strip()
            if line.startswith('#') or not line:  # Skip comments and empty lines
                continue
                
            if line.startswith('application:'):
                app_name = line.split(':', 1)[1].strip()
            elif line.startswith('component:'):
                component_name = line.split(':', 1)[1].strip()
        
        if not app_name:
            return []
            
        # Create the pairs
        pairs = [{'app_name': app_name, 'component_name': None}]  # App-level check
        
        if component_name:
            pairs.append({'app_name': app_name, 'component_name': component_name})
            
        return pairs
    
    @staticmethod
    def _parse_yaml(content: str, file_path: str) -> List[Dict[str, Any]]:
        """Parse YAML format with deployment groups, applications and components"""
        try:
            data = yaml.safe_load(content)
            
            if not data or not isinstance(data, dict) or 'DeploymentGroups' not in data:
                print(f"Warning: Invalid YAML format in {file_path}, missing DeploymentGroups")
                return []
                
            pairs = []
            
            # Process each deployment group
            for group in data.get('DeploymentGroups', []):
                app_name = group.get('AppName')
                if not app_name:
                    continue
                    
                # Add application-level check
                pairs.append({'app_name': app_name, 'component_name': None})
                
                # Add component-level checks
                for component in group.get('Components', []):
                    component_name = component.get('ComponentName')
                    if component_name:
                        pairs.append({'app_name': app_name, 'component_name': component_name})
            
            return pairs
        except Exception as e:
            print(f"Error parsing YAML core-structure: {str(e)}")
            traceback.print_exc()
            return []

def read_core_structure(directory: str = "Phoenix-Security") -> List[Dict[str, Any]]:
    """
    Read the core-structure file to get application and component names
    Returns: List of dicts containing app_name and component_name (optional)
    """
    try:
        # Check for different possible filenames
        file_paths = [
            os.path.join(directory, "core-structure"),
            os.path.join(directory, "core-structure.yaml"),
            os.path.join(directory, "core-structure.yml")
        ]
        
        for file_path in file_paths:
            if os.path.exists(file_path):
                return CoreStructureParser.parse(file_path)
                
        print(f"Warning: No core-structure file found in {directory}")
        return []
    except Exception as e:
        print(f"Error reading core-structure file: {str(e)}")
        traceback.print_exc()
        return []

def find_policy_file(directory: str = "Phoenix-Security") -> Optional[str]:
    """Find policy file in the Phoenix-Security directory"""
    try:
        policy_files = [
            os.path.join(directory, "policy.json"),
            os.path.join(directory, "phoenix-policy.json"),
        ]
        
        for file_path in policy_files:
            if os.path.exists(file_path):
                return file_path
                
        print(f"Warning: No policy file found in {directory}")
        return None
    except Exception as e:
        print(f"Error finding policy file: {str(e)}")
        return None

def format_github_step_output(results_list: List[Dict[str, Any]]) -> None:
    """
    Format the results for GitHub Actions output
    Sets the following GitHub outputs:
    - gate_passed: true/false (overall status)
    - gate_results: JSON string with all evaluation details
    - individual_results: JSON array containing results for each entity
    """
    # Calculate overall status (passed only if all entities passed)
    all_passed = all(result.get("overall_passed", False) for result in results_list)
    
    # Create summarized results with entity names
    summary_results = []
    for result in results_list:
        entity_name = result.get("entity_name", "Unknown")
        entity_passed = result.get("overall_passed", False)
        summary_results.append({
            "entity_name": entity_name,
            "passed": entity_passed,
        })
    
    # Escape multiline strings for GitHub Actions
    with open(os.environ.get('GITHUB_OUTPUT', '/dev/null'), 'a') as f:
        f.write(f"gate_passed={str(all_passed).lower()}\n")
        
        # Provide summary as GH output
        summary = json.dumps({
            "overall_passed": all_passed,
            "entity_results": summary_results
        })
        f.write(f"gate_results<<EOF\n{summary}\nEOF\n")
        
        # Provide detailed results
        detailed_results = json.dumps(results_list)
        f.write(f"individual_results<<EOF\n{detailed_results}\nEOF\n")

def format_github_summary(results_list: List[Dict[str, Any]]) -> None:
    """
    Format the results as GitHub step summary with Markdown formatting
    """
    # Calculate overall status
    all_passed = all(result.get("overall_passed", False) for result in results_list)
    
    # Create summary markdown content
    md_lines = []
    md_lines.append(f"# Phoenix Security Policy Gate: {'PASSED' if all_passed else 'FAILED'}")
    md_lines.append(f"Evaluated {len(results_list)} entities.")
    
    # Add overall table summary
    md_lines.append("\n## Entity Results")
    md_lines.append("| Entity | Status | Required Gates | Optional Gates |")
    md_lines.append("|--------|--------|---------------|----------------|")
    
    for result in results_list:
        entity_name = result.get('entity_name', 'Unknown')
        passed = result.get('overall_passed', False)
        status = "✅ PASS" if passed else "❌ FAIL"
        
        # Count required and optional gates
        evaluations = result.get('evaluations', [])
        required_gates = sum(1 for e in evaluations if e.get('required') == 'must')
        optional_gates = len(evaluations) - required_gates
        
        # Count failed gates
        failed_required = sum(1 for e in evaluations 
                             if e.get('required') == 'must' and not e.get('passed', False))
        failed_optional = sum(1 for e in evaluations 
                             if e.get('required') != 'must' and not e.get('passed', False))
        
        req_status = f"{required_gates - failed_required}/{required_gates} passed"
        opt_status = f"{optional_gates - failed_optional}/{optional_gates} passed"
        
        md_lines.append(f"| {entity_name} | {status} | {req_status} | {opt_status} |")
    
    # Add detailed results for each entity
    for result in results_list:
        entity_name = result.get('entity_name', 'Unknown')
        passed = result.get('overall_passed', False)
        policy = result.get("policy", {})
        pass_logic = policy.get("pass_logic", "REQUIRED")
        evaluations = result.get("evaluations", [])
        
        md_lines.append(f"\n## Details: {entity_name}")
        md_lines.append(f"Status: **{'PASSED' if passed else 'FAILED'}**")
        md_lines.append(f"Pass Logic: **{pass_logic}**")
        
        if pass_logic == "REQUIRED":
            md_lines.append("_Only required gates must pass, optional gates may fail_")
        else:
            md_lines.append("_All gates must pass_")
        
        # Create markdown table for this entity
        md_lines.append("\n### Gate Evaluation Results")
        md_lines.append("| SEVERITY | THRESHOLD | ACTUAL | COMPARISON | REQUIRED | STATUS |")
        md_lines.append("|----------|-----------|--------|------------|----------|--------|")
        
        for eval in evaluations:
            severity = eval["severity"].upper()
            threshold = str(eval["threshold"])
            actual = str(eval["actual"])
            comparison = eval["comparison"]
            required = eval["required"].upper()
            status = "PASS" if eval["passed"] else "FAIL"
            
            # Format comparison for markdown
            if comparison == "=":
                comp_md = comparison
            elif comparison.startswith("-"):
                comp_md = f"{comparison} 👍"  # Good - under threshold
            else:  # starts with +
                comp_md = f"{comparison} 👎"  # Bad - over threshold
            
            # Format status for markdown
            if not eval["passed"] and eval["required"] != "must" and pass_logic == "REQUIRED":
                status_md = f"{status}*"  # Mark optional failures
            else:
                status_md = f"**{status}**"
            
            md_lines.append(f"| {severity} | {threshold} | {actual} | {comp_md} | {required} | {status_md} |")
        
        # Add legend if needed
        has_optional_failures = any(not e["passed"] and e["required"] != "must" 
                                 for e in evaluations)
        if has_optional_failures and pass_logic == "REQUIRED":
            md_lines.append("\n\\* Optional gate failures don't affect overall status with REQUIRED pass logic")
        
        # Add explanation for this entity
        if pass_logic == "ALL":
            if passed:
                md_lines.append("\n✅ **PASS**: All gates have passed.")
            else:
                md_lines.append("\n❌ **FAIL**: Not all gates have passed.")
                
                # List the failures
                md_lines.append("\nFailed Gates:")
                for eval in evaluations:
                    if not eval["passed"]:
                        severity = eval["severity"].upper()
                        msg = f"- **{severity}**: Threshold {eval['threshold']}, Actual {eval['actual']} ({eval['comparison']})"
                        if eval["required"] == "must":
                            msg += " (Required Gate)"
                        md_lines.append(msg)
        else:  # REQUIRED logic
            if passed:
                md_lines.append("\n✅ **PASS**: All required gates have passed.")
                # Show optional gate failures if any
                failed_optional = [e for e in evaluations if not e["passed"] and e["required"] != "must"]
                if failed_optional:
                    md_lines.append("\nNote: The following optional gates failed but do not affect the overall status:")
                    for eval in failed_optional:
                        severity = eval["severity"].upper()
                        md_lines.append(f"- **{severity}**: Threshold {eval['threshold']}, Actual {eval['actual']} ({eval['comparison']})")
            else:
                md_lines.append("\n❌ **FAIL**: One or more required gates have failed.")
                
                # List the failures
                md_lines.append("\nFailed Required Gates:")
                for eval in evaluations:
                    if not eval["passed"] and eval["required"] == "must":
                        severity = eval["severity"].upper()
                        md_lines.append(f"- **{severity}**: Threshold {eval['threshold']}, Actual {eval['actual']} ({eval['comparison']})")
    
    # Write to summary file
    with open(os.environ.get('GITHUB_STEP_SUMMARY', '/dev/null'), 'a') as f:
        f.write('\n'.join(md_lines))

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
    pass_logic = policy.get("pass_logic", "REQUIRED")
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
                              policy.get("pass_logic", "REQUIRED") == "REQUIRED")
        
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
    if has_optional_failures and policy.get("pass_logic", "REQUIRED") == "REQUIRED":
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

def process_entity_check(entity_type: str, name: str, app_name: str, policy_file: str, token: str, base_url: str) -> Dict[str, Any]:
    """Process a single entity check and return the results"""
    entity_name = f"Component: {name} (Application: {app_name})" if entity_type == 'component' else f"Application: {name}"
    print(f"\nEvaluating: {entity_name}")
    
    # Create policy gate
    gate = PolicyGate(policy_file)
    
    # Get vulnerability counts
    counts = get_vulnerability_counts(entity_type, name, app_name, token, base_url)
    
    # Evaluate gate
    passed, details = gate.evaluate_gate(counts, entity_name)
    
    # Print results to console
    print_gate_results(passed, details)
    
    return details

def run_multiple_checks() -> List[Dict[str, Any]]:
    """Run multiple policy checks based on core-structure and return all results"""
    # Setup configuration
    base_url = os.environ.get("PHOENIX_API_URL", "https://api.poc1.appsecphx.io")
    
    # Get application and component info from overrides or core-structure
    app_override = os.environ.get("APPLICATION_OVERRIDE")
    comp_override = os.environ.get("COMPONENT_OVERRIDE")
    
    # If specific overrides are provided, just run those
    if app_override:
        entities = []
        if comp_override:
            # Only run the specific component
            entities.append({
                'app_name': app_override,
                'component_name': comp_override
            })
        else:
            # Run the application only
            entities.append({
                'app_name': app_override,
                'component_name': None
            })
    else:
        # Read from core-structure
        entities = read_core_structure()
    
    if not entities:
        print("Error: No application/component information found.")
        print("Either set APPLICATION_OVERRIDE or ensure core-structure file exists.")
        sys.exit(1)
    
    # Find policy file
    policy_file = find_policy_file()
    
    # Get token for API requests
    token = get_access_token()
    
    # Process each entity and collect results
    results = []
    overall_passed = True
    
    for entity in entities:
        app_name = entity.get('app_name')
        comp_name = entity.get('component_name')
        
        if not app_name:
            print("Error: Missing application name for an entity.")
            continue
        
        # Run application or component check
        if comp_name:
            result = process_entity_check('component', comp_name, app_name, policy_file, token, base_url)
        else:
            result = process_entity_check('application', app_name, app_name, policy_file, token, base_url)
        
        results.append(result)
        
        # Update overall status
        if not result.get('overall_passed', True):
            overall_passed = False
    
    return results

def main():
    print("Starting Phoenix Policy Gate GitHub Action")
    
    try:
        # Run all checks
        results = run_multiple_checks()
        
        # Format results for GitHub Actions
        format_github_step_output(results)
        format_github_summary(results)
        
        # Determine overall status
        overall_passed = all(result.get('overall_passed', False) for result in results)
        
        # Print overall summary
        print("\n" + "="*60)
        print(f"OVERALL GATE STATUS: {'PASSED' if overall_passed else 'FAILED'}")
        print("="*60)
        
        for result in results:
            entity_name = result.get('entity_name', 'Unknown')
            entity_passed = result.get('overall_passed', False)
            status = "PASSED" if entity_passed else "FAILED"
            print(f"- {entity_name}: {status}")
        
        # Exit with status code based on gate result for CI/CD pass/fail
        if not overall_passed:
            print("\nOne or more policy gates failed - setting exit code 1")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error running policy gate checks: {str(e)}")
        traceback.print_exc()
        sys.exit(1)
    
if __name__ == "__main__":
    main() 