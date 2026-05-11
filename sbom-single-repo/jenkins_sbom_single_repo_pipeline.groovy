pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    parameters {
        string(name: 'CONTAINER_IMAGE', defaultValue: 'nginx:latest', description: 'Image to scan into CycloneDX SBOM')
        string(name: 'REPO_NAME', defaultValue: 'acme/payments', description: 'Repository identifier')
        string(name: 'FILE_PATH', defaultValue: 'package-lock.json', description: 'Repository file/manifest path')
        string(name: 'BRANCH', defaultValue: 'main', description: 'Repository branch')
        choice(name: 'PHOENIX_IMPORT_TYPE', choices: ['new', 'merge', 'delta'], description: 'Phoenix import type')
        string(name: 'PHOENIX_API_BASE_URL', defaultValue: 'https://api.securityphoenix.cloud', description: 'Phoenix API URL')
    }

    environment {
        PHOENIX_CLIENT_ID = credentials('phoenix-client-id')
        PHOENIX_CLIENT_SECRET = credentials('phoenix-client-secret')
        SBOM_FILE = "${WORKSPACE}/sbom.cdx.json"
    }

    stages {
        stage('Generate CycloneDX SBOM') {
            steps {
                sh '''
                    set -euo pipefail
                    docker run --rm \
                        -v /var/run/docker.sock:/var/run/docker.sock \
                        -v "$WORKSPACE:/workspace" \
                        aquasec/trivy:latest image \
                        --format cyclonedx \
                        --output /workspace/sbom.cdx.json \
                        "$CONTAINER_IMAGE"
                '''
            }
        }

        stage('Import to Phoenix as single repo asset') {
            steps {
                sh '''
                    set -euo pipefail
                    cd "Utils/sca-pipeline/sbom-single-repo"
                    python3 -m pip install -r requirements.txt

                    export PHOENIX_CLIENT_ID="$PHOENIX_CLIENT_ID"
                    export PHOENIX_CLIENT_SECRET="$PHOENIX_CLIENT_SECRET"
                    export PHOENIX_API_BASE_URL="$PHOENIX_API_BASE_URL"

                    python3 sbom_sca_single_repo_to_phoenix.py \
                        --sbom-file "$SBOM_FILE" \
                        --repo "$REPO_NAME" \
                        --file-path "$FILE_PATH" \
                        --branch "$BRANCH" \
                        --import-type "$PHOENIX_IMPORT_TYPE"
                '''
            }
        }
    }

    post {
        always {
            sh 'rm -f "$SBOM_FILE"'
        }
    }
}
