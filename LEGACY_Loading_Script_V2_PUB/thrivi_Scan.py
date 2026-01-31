import requests
from requests.auth import HTTPBasicAuth
import json
import os

def get_access_token(client_id, client_secret):
    url = "https://api.<yourdomain>.io/v1/auth/access_token"
    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        return response.json()['token']
    else:
        print(response.status_code)
        print("Failed to obtain token:", response.text)
    return None

def send_results(file_path, scan_type, assessment_name, import_type, client_id,client_secret, scan_target=None, auto_import=True):
    token = get_access_token(client_id, client_secret)
    if token is None:
        return
    url = "https://api.<yourdomain>/v1/import/assets/file/translate"
    headers = {
        'Authorization': f'Bearer {token}'
    }
    files = {
        'file': (file_path, open(file_path, 'rb'), 'application/octet-stream')
    }
    data = {
        'scanType': scan_type,
        'assessmentName': assessment_name,
        'importType': import_type,
        'scanTarget': scan_target if scan_target else '',
        'autoImport': 'true' if auto_import else 'false'
    }
    response = requests.post(url, headers=headers, files=files, data=data)
    files['file'][1].close() # Make sure to close the file
    print("Status Code:", response.status_code)
    print("Response:", response.json())

# Example usage
#your api token for Phoenix
client_id = "****"
client_secret = "pat1_***"
#send_results('path_to_your_report_file.ext', 'YourScanType', 'YourAssessmentName', 'new', client_id, client_secret, scan_target)
send_results('trivy_mix.json', 'trivi Scan', 'ImportNightmare', 'new', client_id, client_secret, "com.example.tests/example:latest")
#use com.example.tests/example:latest for the container name
