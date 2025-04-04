#!/usr/bin/env python3
import os
import sys
import csv
import json
import requests
from requests.auth import HTTPBasicAuth

############################
# PHOENIX HELPER FUNCTIONS #
############################

def get_access_token(client_id, client_secret, base_url="https://api.demo.appsecphx.io"):
    """
    Obtains a time-limited access token from the Phoenix platform via Basic Auth.
    If client_id or client_secret are missing, the user is prompted once and stored.
    
    :param client_id: Phoenix API Client ID
    :param client_secret: Phoenix API Client Secret
    :param base_url: The base URL for Phoenix Security API
    :return: The Bearer token string, or None if authentication failed.
    """
    # Prompt if missing
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
        payload = response.json()
        token = payload.get('token')
        expiry = payload.get('expiry')
        print(f"Token expires at: {expiry} (Unix timestamp)")
        return token
    else:
        print(f"Failed to obtain token: HTTP {response.status_code}")
        print("Response:", response.text)
    return None

def get_application_posture(application_name, token, base_url, exclude_risk_accepted=None):
    """
    Gets the application's risk posture
    
    :param application_name: Name of the application
    :param token: Authentication token
    :param base_url: Base URL for Phoenix Security API
    :param exclude_risk_accepted: Whether to exclude risk-accepted vulnerabilities
    :return: JSON response with posture data
    """
    import_url = f"{base_url}/v1/applications/posture"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    payload = {
        'applicationSelector': {'name': application_name}
    }
    if exclude_risk_accepted is not None:
        payload['excludeRiskAccepted'] = exclude_risk_accepted

    print(f"\nSending request to: {import_url}")
    print(f"Request payload: {json.dumps(payload, indent=2)}")
    
    response = requests.post(import_url, headers=headers, json=payload)
    return response

def get_component_posture(application_name, component_name, token, base_url, exclude_risk_accepted=None):
    """
    Gets the component's risk posture
    
    :param application_name: Name of the application
    :param component_name: Name of the component
    :param token: Authentication token
    :param base_url: Base URL for Phoenix Security API
    :param exclude_risk_accepted: Whether to exclude risk-accepted vulnerabilities
    :return: JSON response with posture data
    """
    import_url = f"{base_url}/v1/components/posture"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    payload = {
        'selector': {
            'applicationSelector': {'name': application_name},
            'componentSelector': {'name': component_name}
        }
    }
    if exclude_risk_accepted is not None:
        payload['excludeRiskAccepted'] = exclude_risk_accepted

    print(f"\nSending request to: {import_url}")
    print(f"Request payload: {json.dumps(payload, indent=2)}")
    
    response = requests.post(import_url, headers=headers, json=payload)
    return response

def get_query_preference():
    """Get and store the user's preference for query type"""
    saved_preference = os.environ.get("PHOENIX_QUERY_TYPE")
    if saved_preference:
        print(f"Using saved preference: {saved_preference}")
        return saved_preference
    
    while True:
        choice = input("What would you like to query? (1: Application, 2: Component): ").strip()
        if choice in ['1', '2']:
            query_type = 'application' if choice == '1' else 'component'
            os.environ["PHOENIX_QUERY_TYPE"] = query_type
            return query_type
        print("Invalid choice. Please enter 1 for Application or 2 for Component.")

def main():
    # Get base configuration
    client_id = os.environ.get("CLIENT_ID", "")
    client_secret = os.environ.get("CLIENT_SECRET", "")
    base_url = "https://api.poc1.appsecphx.io"

    # Get query preference
    query_type = get_query_preference()
    
    # Get names based on query type
    if query_type == 'component':
        comp_name = input("Enter the component name: ").strip()
        app_name = input("Enter the application name containing this component: ").strip()
    else:
        app_name = input("Enter the application name: ").strip()
        comp_name = None

    # Get token
    token = get_access_token(client_id, client_secret, base_url=base_url)
    if not token:
        print("Failed to obtain token. Exiting.")
        return

    print("\n=== Fetching vulnerabilities (including risk-accepted) ===")
    if query_type == 'application':
        response = get_application_posture(app_name, token, base_url, exclude_risk_accepted=False)
    else:
        response = get_component_posture(app_name, comp_name, token, base_url, exclude_risk_accepted=False)

    if response.status_code in [200, 201]:
        print("\nComplete vulnerability data (including risk-accepted):")
        print(json.dumps(response.json(), indent=4))
    else:
        print(f"\nError fetching data: HTTP {response.status_code}")
        try:
            error_data = response.json()
            print("Error details:", json.dumps(error_data, indent=2))
        except:
            print("Response text:", response.text)
        if response.status_code == 404:
            print("\nTroubleshooting 404 Not Found:")
            print("1. Verify the application/component name is exactly as registered in Phoenix Security (case-sensitive)")
            print("2. Check that you're using the correct environment URL")
            print("3. Ensure the application/component exists in this environment")
            print(f"4. Current environment: {base_url}")
        return

    print("\n=== Fetching vulnerabilities (excluding risk-accepted) ===")
    if query_type == 'application':
        response = get_application_posture(app_name, token, base_url, exclude_risk_accepted=True)
    else:
        response = get_component_posture(app_name, comp_name, token, base_url, exclude_risk_accepted=True)

    if response.status_code in [200, 201]:
        print("\nVulnerability data (excluding risk-accepted):")
        print(json.dumps(response.json(), indent=4))
    else:
        print(f"\nError fetching data: HTTP {response.status_code}")
        try:
            error_data = response.json()
            print("Error details:", json.dumps(error_data, indent=2))
        except:
            print("Response text:", response.text)

if __name__ == "__main__":
    main() 