Utilities and script to simplify the upload of phoenix config

# Phoenix Import Script

A Python script for importing SonarQube scan results into the Phoenix Security platform. This script automates the process of uploading scan results, validating scanner types, and monitoring the import process.

## Features

- Upload Scanner scan results to Phoenix Security
- Validate scanner types against a predefined list
- Suggest closest matching scanner type if an invalid type is provided
- Monitor import status with configurable polling intervals
- Support for both automatic and manual import processes
- Configurable timeout for import completion

## Prerequisites

- Python 3.6+
- Required Python packages:
  - requests
  - difflib

## Installation

1. Clone this repository or download the script
2. Install the required dependencies:

```bash
pip install requests
```

## Configuration

The script uses several configuration parameters that can be modified at the top of the file:

```python
# API Configuration
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"
API_BASE_URL = "https://api.YOURDOMAIN.securityphoenix.com"
API_BASE_URL = "https://api.demo.appsecphx.io"


# Import Parameters
FILE_PATH = 'path-to-your-scan-file.json'
SCAN_TYPE = 'Scannerns' #check /Loading Script/Scanner_Selection.txt
ASSESSMENT_NAME = 'Your Assessment Name'
IMPORT_TYPE = 'new'  # or 'merge'
SCAN_TARGET = 'your-scan-target.com'
AUTO_IMPORT = True
WAIT_FOR_COMPLETION = True

# Scanner types file path
SCANNER_TYPES_FILE = 'path/to/Scanner_Selection.txt'
```

## Scanner Types Validation

The script validates scanner types against a predefined list stored in a text file. The file should contain one scanner type per line. If an invalid scanner type is provided, the script will suggest the closest matching type.

## Usage

### Basic Usage

```python
from sonarqube_import import send_results

request_id, final_status = send_results(
    FILE_PATH, 
    SCAN_TYPE, 
    ASSESSMENT_NAME, 
    IMPORT_TYPE, 
    CLIENT_ID, 
    CLIENT_SECRET, 
    SCAN_TARGET,
    AUTO_IMPORT,
    WAIT_FOR_COMPLETION
)
```

### Without Waiting for Completion

```python
request_id, response = send_results(
    FILE_PATH, 
    SCAN_TYPE, 
    ASSESSMENT_NAME, 
    IMPORT_TYPE, 
    CLIENT_ID, 
    CLIENT_SECRET, 
    SCAN_TARGET,
    AUTO_IMPORT,
    False  # Don't wait for completion
)

# Check status manually later
if request_id:
    status = check_import_status(request_id, CLIENT_ID, CLIENT_SECRET)
    print(f"Current status: {status.get('status')}")
```

## Functions

### `load_scanner_types(file_path)`

Loads valid scanner types from the specified file.

### `find_closest_scanner_type(scanner_type, valid_scanner_types)`

Finds the closest matching scanner type from the list of valid types.

### `validate_scanner_type(scanner_type)`

Validates if the provided scanner type is in the list of valid types and suggests the closest match if not.

### `get_access_token(client_id, client_secret)`

Obtains an access token for API authentication.

### `check_import_status(request_id, client_id, client_secret)`

Checks the status of an import request.

### `wait_for_import_completion(request_id, client_id, client_secret, check_interval=10, timeout=3600)`

Continuously checks the status of an import until it completes or times out.

### `send_results(file_path, scan_type, assessment_name, import_type, client_id, client_secret, scan_target=None, auto_import=True, wait_for_completion=True)`

Sends scan results to the API and optionally waits for the import to complete.

## Error Handling

The script includes error handling for:
- File not found errors when loading scanner types
- API authentication failures
- Import status check failures
- Import timeouts

## Security Considerations

- The script contains hardcoded client ID and client secret. In a production environment, these should be stored securely (e.g., environment variables or a secure vault).
- The script uses HTTPS for API communication.

## License


You can fork this file and modify it at will, mention the author and always refer back to the code 

## Contributing

You can provide your contribution and pull request that will be reviewed by Phoenix security engineering team
