import requests
from requests.auth import HTTPBasicAuth
import json
import os

def get_access_token(client_id, client_secret):
# The line `url = "https://api.https://demo2.appsecphx.io//v1/auth/access_token"` is defining the URL
# endpoint for obtaining an access token. This URL is used in the `get_access_token` function to make
# a GET request with HTTP basic authentication using the provided client ID and client secret. The
# response from this URL is expected to contain the access token needed for authentication in
# subsequent API requests.
    url = "https://api.demo.appsecphx.io/v1/auth/access_token"
    #url = "https://api.poc1.appsecphx.io/v1/auth/access_token"

    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        return response.json()['token']
    else:
        print(response.status_code)
        print("Failed to obtain token:", response.text)
    return None

    """
    The function `send_results` sends scan results to a specified API endpoint using a file path and
    other parameters.
    
    :param file_path: The `file_path` parameter in the `send_results` function represents the path to
    the file that you want to send for processing. It should be a string that specifies the location of
    the file on your system. For example, it could be something like "/path/to/your/file.txt"
    :param scan_type: Scan type refers to the type of scan being performed, such as "web application
    scan" or "network scan". It helps identify the purpose or focus of the scan being conducted
    :param assessment_name: Assessment_name is a parameter that represents the name of the assessment
    being conducted or the assessment file being imported. It is a user-defined name that helps identify
    the specific assessment or scan being performed
    :param import_type: The `import_type` parameter in the `send_results` function specifies the type of
    import being performed. It is used to indicate how the file should be imported or processed by the
    API. This parameter helps the API understand the format or method to use when handling the file
    data. It could be values
    :param client_id: Client ID is a unique identifier assigned to a client application when it is
    registered with the API provider. It is used to authenticate the client application when making
    requests to the API
    :param client_secret: It seems like you were about to ask something related to the `client_secret`
    parameter in the `send_results` function. How can I assist you further with this parameter or any
    other aspect of the function?
    :param scan_target: The `scan_target` parameter in the `send_results` function is used to specify
    the target for the scan. It is an optional parameter, so if a value is not provided, it defaults to
    an empty string (''). This parameter allows you to specify the target of the scan, such as a
    :param auto_import: The `auto_import` parameter in the `send_results` function is a boolean
    parameter that specifies whether the imported assets should be automatically imported. If
    `auto_import` is set to `True`, the assets will be automatically imported; if set to `False`, manual
    intervention may be required for importing the, defaults to True (optional)
    :return: The `send_results` function returns nothing explicitly. It either returns `None` if the
    access token is not obtained successfully or it completes the HTTP POST request to the specified URL
    and prints the status code and response JSON.
    """
def send_results(file_path, scan_type, assessment_name, import_type, client_id,client_secret, scan_target=None, auto_import=True):
    token = get_access_token(client_id, client_secret)
    if token is None:
        return
    url = "https://api.demo.appsecphx.io/v1/import/assets/file/translate"
    #url = " https://api.poc1.appsecphx.io/v1/import/assets/file/translate"    

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
#client_id = os.environ["CLIENT_ID"]
#client_secret = os.environ["CLIENT_SECRET"]

client_id = "18f9ba6d-2308-4a7c-a170-666e8d669f8d"
client_secret = "pat1_52834767216c4a46bb714ebd47e4f60e36c79b011a1d4d0982f705e42ad1a4f9"

#send_results('path_to_your_report_file.ext', 'YourScanType', 'YourAssessmentName', 'new', client_id, client_secret, scan_target)

send_results('owasp-benchmarkjava.json', 'SonarQube', 'Container_pipeline_assesm1', 'new', client_id, client_secret, 'owasp.benchmark.volvo.com')