pipeline {
    agent any

    environment {
        WORKSPACE_DIR = "${env.WORKSPACE}"
    }

    stages {
        stage('Checkout Repository') {
            steps {
                // Git checkout
                checkout scm
            }
        }

        stage('Prepare Output Folder') {
            steps {
                sh 'mkdir -p outputs'
            }
        }

        stage('Run Git Security Tool (Gitleaks + Semgrep + YARA)') {
            steps {
                sh '''
                    docker run --rm \
                      -v $WORKSPACE_DIR:/app/code \
                      -v $WORKSPACE_DIR/outputs:/app/outputs \
                      -v $WORKSPACE_DIR/configs:/app/configs \
                      -v $WORKSPACE_DIR/configs/gitleaks.toml:/gitleaks.toml \
                      eliechxh/git-salus-scanner
                '''
            }
        }

        stage('Archive Scan Reports') {
            steps {
                archiveArtifacts artifacts: 'outputs/**', fingerprint: true
            }
        }
    }

    post {
        failure {
            echo '❌ Pipeline failed due to threat detection or error.'
        }
        success {
            echo '✅ Scan completed successfully with no verified threats.'
        }
    }
}
