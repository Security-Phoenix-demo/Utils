#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth
import json
import os
import argparse
import sys

def get_access_token(client_id, client_secret, phoenix_url):
    """Get an access token from Phoenix."""
    url = f"{phoenix_url}/v1/auth/access_token"
    
    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        return response.json()['token']
    else:
        print(f"Status code: {response.status_code}")
        print(f"Failed to obtain token: {response.text}")
        return None

def send_results(file_path, scan_type, assessment_name, import_type, client_id, client_secret, 
                scan_target=None, auto_import=True, phoenix_url="https://api.poc1.appsecphx.io"):
    """Send scan results to Phoenix."""
    token = get_access_token(client_id, client_secret, phoenix_url)
    if token is None:
        return False
    
    url = f"{phoenix_url}/v1/import/assets/file/translate"
    
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    try:
        with open(file_path, 'rb') as f:
            files = {
                'file': (os.path.basename(file_path), f, 'application/json')
            }
            
            data = {
                'scanType': scan_type,
                'assessmentName': assessment_name,
                'importType': import_type,
                'scanTarget': scan_target if scan_target else '',
                'autoImport': 'true' if auto_import else 'false'
            }
            
            response = requests.post(url, headers=headers, files=files, data=data)
            
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            
            return response.status_code == 200
    except Exception as e:
        print(f"Error sending results: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Send SonarQube results to Phoenix')
    parser.add_argument('--file', required=True, help='Path to the SonarQube JSON report file')
    parser.add_argument('--scan-type', default='sonarqube', help='Type of scan')
    parser.add_argument('--assessment-name', required=True, help='Name of the assessment')
    parser.add_argument('--import-type', default='new', help='Import type')
    parser.add_argument('--client-id', required=True, help='Phoenix client ID')
    parser.add_argument('--client-secret', required=True, help='Phoenix client secret')
    parser.add_argument('--scan-target', help='Target of the scan')
    parser.add_argument('--auto-import', action='store_true', default=True, help='Auto import assets')
    parser.add_argument('--phoenix-url', default='https://api.poc1.appsecphx.io', help='Phoenix API URL')
    
    args = parser.parse_args()
    
    success = send_results(
        args.file,
        args.scan_type,
        args.assessment_name,
        args.import_type,
        args.client_id,
        args.client_secret,
        args.scan_target,
        args.auto_import,
        args.phoenix_url
    )
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

