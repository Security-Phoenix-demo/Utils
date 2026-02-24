# SonarQube to Phoenix Integration

This integration allows you to automatically send SonarQube scan results to Phoenix for security analysis and reporting.

## Prerequisites

1. Jenkins server with the following plugins installed:
   - SonarQube Scanner
   - Credentials Plugin
   - Pipeline Plugin

2. SonarQube server configured and accessible

3. Phoenix API credentials (client ID and client secret)

4. Python 3.6+ installed on the Jenkins agent

5. Required Python packages:
   ```
   pip install requests
   ```

## Setup Instructions

### 1. Configure Jenkins Credentials

Add the following credentials to Jenkins:

- `sonarqube`: SonarQube token (Secret text)
- `phoenix-client-id`: Phoenix client ID (Secret text)
- `phoenix-client-secret`: Phoenix client secret (Secret text)
- `git-credentials`: Git repository credentials (Username with password)

### 2. Configure the Pipeline

1. Create a new Pipeline job in Jenkins
2. Copy the contents of `sonarqube_phoenix_pipeline.groovy` into the pipeline script
3. Update the following environment variables in the pipeline:
   - `PROJECT_NAME`: Your SonarQube project key
   - `SONAR_HOST_URL`: Your SonarQube server URL
   - Git repository URL in the checkout stage

### 3. Deploy the Python Script

1. Copy the `sonarqube_import.py` script to your Jenkins workspace
2. Make sure the script is executable:
   ```
   chmod +x sonarqube_import.py
   ```

## How It Works

The pipeline performs the following steps:

1. **Checkout**: Clones the repository to be analyzed
2. **SonarQube Analysis**: Runs the SonarQube scanner on the codebase
3. **Generate SonarQube JSON Report**: Extracts the scan results in JSON format
4. **Send Results to Phoenix**: Uses the Python script to send the results to Phoenix

## Customization

You can customize the pipeline by:

- Changing the SonarQube scanner parameters
- Modifying the JSON report extraction process
- Adjusting the Phoenix import parameters

## Troubleshooting

If you encounter issues:

1. Check the Jenkins console output for error messages
2. Verify that all credentials are correctly configured
3. Ensure the SonarQube server is accessible from the Jenkins agent
4. Check that the Python script has the required permissions

## Support

For issues or questions, please contact your Phoenix administrator or refer to the Phoenix documentation. 