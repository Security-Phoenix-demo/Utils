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
    :param base_url: The base URL for Phoenix Security. For SaaS production,
                     use "https://api.securityphoenix.cloud". For demos,
                     "https://api.demo.appsecphx.io", or
                     "https://api.poc1.appsecphx.io" for enterprise PoC.
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

    # Access token endpoint
    url = f"{base_url}/v1/auth/access_token"
    print(f"Requesting Phoenix token from: {url}")

    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        payload = response.json()
        token = payload.get('token')
        expiry = payload.get('expiry')  # Unix timestamp
        print(f"Token expires at: {expiry} (Unix timestamp)")
        return token
    else:
        print(f"Failed to obtain token: HTTP {response.status_code}")
        print("Response:", response.text)
    return None

def get_posture(
    application_name,
    component_name,
    client_id,
    client_secret,
    base_url="https://api.demo.appsecphx.io"
):
    """
    Gets the application's risk posture

    :param aplication_name: the name of the application that contains the component
    :param component_name: the name of the component to obtain posture for
    :param client_id: Phoenix Client ID
    :param client_secret: Phoenix Client Secret
    :param base_url: Base URL for Phoenix Security API
    """
    # Obtain a Bearer token from Phoenix
    token = get_access_token(client_id, client_secret, base_url=base_url)
    if token is None:
        print("Could not retrieve token. Exiting upload.")
        return

    # Final import endpoint
    import_url = f"{base_url}/v1/components/posture"
    print(f"Fetching data from: {import_url}")

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    # Prepare the payload
    payload = {
        'selector': {
            'applicationSelector': {'name': application_name},
            'componentSelector': {'name': component_name}
        },
        'excludeRiskAccepted': True
    }

    response = requests.post(import_url, headers=headers, json=payload)

    if response.status_code in [200, 201]:
        try:
            print(f"\n\"{component_name}\" (in \"{application_name}\") risk posture:\n", json.dumps(response.json(), indent = 4), "\n")
        except:
            print("Response text:", response.text)
    elif response.status_code == 401:
        print("401 Unauthorized. Token may have expired or credentials invalid.")
    else:
        print(f"Error fetching data: {response}")


def main():
    app_name = "SPHX_Deployment"
    comp_name = "backend"

    # Prompt once for client_id/client_secret if not in environment.
    client_id = os.environ.get("CLIENT_ID", "")
    client_secret = os.environ.get("CLIENT_SECRET", "")
    print(f"\nFetching component posture for \"{comp_name}\" in \"{app_name}\"...")

    # Adjust base_url as needed, e.g. for production: base_url="https://api.securityphoenix.cloud"
    get_posture(
        application_name=app_name,
        component_name=comp_name,
        client_id=client_id,
        client_secret=client_secret,
        base_url="https://api.poc1.appsecphx.io"
    )

if __name__ == "__main__":
    main()
