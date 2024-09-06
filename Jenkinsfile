pipeline {
    agent {
        docker {
            image 'python:3.12-alpine'
            reuseNode true
        }
    }
    stages {
        stage('build') {
            steps {
                sh 'python -m venv venv && source venv/bin/activate && python -m pip install -r requirements.txt'
            }
        }
        stage('execute') {
            steps {
                script {
                    env.IN_DOCKER = 'true'
                }
                sh 'source venv/bin/activate && python XIQ-AD-PPSK-Sync.py'
            }
        }
    }
         post {
//          always {
//              echo 'This will always run'
//          }
//          success {
//              echo 'This will run only if successful'
//          }
         failure {
            script {
                def buildCause = currentBuild.getBuildCauses()[0]?.shortDescription ?: "Unknown"
                emailext(
                    subject: "Jenkins Build Failed: ${env.JOB_NAME} #${env.BUILD_NUMBER} - Reason: ${currentBuild.currentResult}",
                    body: """
                        <p>Build ${env.BUILD_NUMBER} of job <a href="${env.BUILD_URL}">${env.JOB_NAME}</a> has failed.</p>
                        <p>Failed in stage: ${env.STAGE_NAME}</p>
                        <p>Duration: ${currentBuild.durationString}</p>
                        <p>Triggered by: ${buildCause}</p>
                        <p>Git Branch: ${env.GIT_BRANCH ?: "Unknown"}</p>
                        <p>Git Commit: ${env.GIT_COMMIT ?: "Unknown"}</p>
                        <p>Git Author: ${env.CHANGE_AUTHOR ?: "Unknown"}</p>
                        <p>Check the console output <a href="${env.BUILD_URL}console">here</a>.</p>
                    """,
                    to: "${env.BUILD_NOTIFICATION_EMAIL_TO}",
                    from: "${env.BUILD_NOTIFICATION_EMAIL_FROM}",
                    attachLog: true
                )
            }
         }
//          unstable {
//              echo 'This will run only if the run was marked as unstable'
//          }
//          changed {
//              echo 'This will run only if the state of the Pipeline has changed'
//              echo 'For example, if the Pipeline was previously failing but is now successful'
//          }
     }
}
