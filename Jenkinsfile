pipeline {
    agent any

    environment {
        ASSESSMENT_TOOL_REPO = 'https://github.com/rahul-avx/assessment-tool.git'
        ASSESSMENT_TOOL_DIR = 'assessment-tool-repo'
        TARGET_REPO_DIR = 'target-repo'
        OUTPUT_DIR = 'output-folder'
    }

    options {
        disableConcurrentBuilds()
    }

    stages {

        stage('Checkout Target Repository') {
            steps {
                echo 'Checking out current repo'
                checkout scm
                sh """
		    mkdir -p ${TARGET_REPO_DIR}
		    shopt -s dotglob
		    for item in *; do
			[ "\$item" != "${TARGET_REPO_DIR}" ] && mv "\$item" "${TARGET_REPO_DIR}/"
		    done
		"""
            }
        }

        stage('Checkout Assessment Tool Repository') {
            steps {
                withCredentials([string(credentialsId: 'PQC_ASSESSMENT_TOOL_PAT', variable: 'GIT_TOKEN')]) {
                    sh """
                        git clone https://${GIT_TOKEN}@github.com/rahul-avx/assessment-tool.git ${ASSESSMENT_TOOL_DIR}
                    """
                }
            }
        }

        stage('Validate Input Folder') {
            steps {
                sh """
                    echo "Validating input folder: ${TARGET_REPO_DIR}"
                    if [ -d "${TARGET_REPO_DIR}" ]; then
                        echo "Input folder exists:"
                        ls -la ${TARGET_REPO_DIR}
                    else
                        echo "Input folder does not exist!"
                        exit 1
                    fi
                """
            }
        }

        stage('Prepare Output Folder') {
            steps {
                sh """
                    mkdir -p ${OUTPUT_DIR}
                    chmod 755 ${OUTPUT_DIR}
                    echo "Output folder prepared:"
                    ls -la ${OUTPUT_DIR} || echo "Empty"
                """
            }
        }

        stage('Run PQC Assessment Tool') {
            steps {
                sh """
                    chmod +x ${ASSESSMENT_TOOL_DIR}/PQC_Assessment_Tool
                    ${ASSESSMENT_TOOL_DIR}/PQC_Assessment_Tool --inputFolder ${TARGET_REPO_DIR} --outputFolder ${OUTPUT_DIR} --configPath ${ASSESSMENT_TOOL_DIR}/config.ini
                """
            }
        }

        stage('Archive CBOM Output') {
            steps {
                archiveArtifacts artifacts: "${OUTPUT_DIR}/**", fingerprint: true
            }
        }

        stage('Publish SARIF (Optional)') {
            when {
                expression { fileExists("${OUTPUT_DIR}/results.sarif") }
            }
            steps {
                echo "SARIF file found. Upload manually or use GitHub upload in a GitHub Actions job if needed."
                // You could integrate with SARIF plugins if needed here
            }
        }
    }

    post {
        failure {
            echo "Pipeline failed. Please check the logs."
        }
    }
}
