pipeline {
    agent {
        label 'Agent-1'
    }

    environment {
        SONAR_TOKEN = credentials('sonarqube')
        PHOENIX_CLIENT_ID = credentials('phoenix-client-id')
        PHOENIX_CLIENT_SECRET = credentials('phoenix-client-secret')
        SONAR_REPORT_FILE = "${WORKSPACE}/sonarqube-report.json"
        PROJECT_NAME = 'YourProjectName'
        SONAR_HOST_URL = 'https://your-sonarqube-instance.com'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout([$class: 'GitSCM', 
                    branches: [[name: 'dev']],
                    userRemoteConfigs: [[credentialsId: 'git-credentials', url: 'https://github.com/your-org/your-repo.git']]
                ])
            }
        }

        stage('SonarQube Analysis') {
            steps {
                script {
                    withSonarQubeEnv('SonarQube') {
                        def scannerHome = tool name: 'sonar-scanner', type: 'hudson.plugins.sonar.SonarRunnerInstallation'
                        def scannerCmd = "${scannerHome}/bin/sonar-scanner"
                        
                        sh """
                            ${scannerCmd} \
                            -Dsonar.projectKey=${PROJECT_NAME} \
                            -Dsonar.sources=./ \
                            -Dsonar.host.url=${SONAR_HOST_URL} \
                            -Dsonar.login=${SONAR_TOKEN} \
                            -Dsonar.java.binaries=./ \
                            -Dsonar.analysis.mode=publish
                        """
                    }
                }
            }
        }

        stage('Generate SonarQube JSON Report') {
            steps {
                script {
                    // Wait for SonarQube to process the analysis
                    sleep(time: 30, unit: 'SECONDS')
                    
                    // Get the latest analysis ID
                    def analysisId = sh(
                        script: """
                            curl -s -u ${SONAR_TOKEN}: \
                            "${SONAR_HOST_URL}/api/project_analyses/search?project=${PROJECT_NAME}&ps=1" | \
                            jq -r '.analyses[0].key'
                        """,
                        returnStdout: true
                    ).trim()
                    
                    // Download the report in JSON format
                    sh """
                        curl -s -u ${SONAR_TOKEN}: \
                        "${SONAR_HOST_URL}/api/issues/search?componentKeys=${PROJECT_NAME}&resolved=false&ps=500" \
                        -o ${SONAR_REPORT_FILE}
                    """
                    
                    // Verify the report was created
                    if (!fileExists(SONAR_REPORT_FILE)) {
                        error "SonarQube report file was not created"
                    }
                }
            }
        }

        stage('Send Results to Phoenix') {
            steps {
                script {
                    // Use the Python script to send results to Phoenix
                    sh """
                        python3 ${WORKSPACE}/Utilis/Loading Script/sonarqube_import.py \
                        --file ${SONAR_REPORT_FILE} \
                        --scan-type sonarqube \
                        --assessment-name "${PROJECT_NAME}-${BUILD_NUMBER}" \
                        --import-type new \
                        --client-id ${PHOENIX_CLIENT_ID} \
                        --client-secret ${PHOENIX_CLIENT_SECRET} \
                        --scan-target "${PROJECT_NAME}"
                    """
                }
            }
        }
    }

    post {
        always {
            // Clean up the report file
            cleanWs()
        }
        success {
            echo "SonarQube analysis completed and results sent to Phoenix successfully"
        }
        failure {
            echo "Pipeline failed. Check the logs for details."
        }
    }
} 