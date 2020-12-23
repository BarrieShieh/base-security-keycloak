#!/usr/bin/env groovy

projectName = ''
projectVersion = ''

technicalUserCredentialsId = 'technical_user'
sonarQubeScanUserCredentialsId = 'rb-sonarqube-scan-user-token'

runPipeline {
    stage('Checkout') {
        checkout scm
    }

    stage('Get project version') {
        script {
            projectName = getMavenProjectArtifactId()
            projectVersion = getMavenProjectVersion()
        }
    }

    onlyOnMasterAndDev {
        stage('Check release note') {
            checkReleaseNote(projectVersion)
        }
    }

    stage('Clean') {
        withMaven() {
            sh "mvn clean"
        }
    }

    stage('Compile') {
        withMaven() {
            sh "mvn compile -DskipTests"
        }
    }

    stage('Tests') {
        withMaven() {
            sh "mvn test"
        }
    }

    stage('Package') {
        withMaven() {
            sh 'mvn package -DskipTests'
        }
    }

//    stage('Nexus IQ analysis') {
//        dir('application') {
//            qualityAnalysisNexusIQ(technicalUserCredentialsId)
//        }
//    }

    stage('SonarQube analysis') {
        qualityAnalysisSonarQube(sonarQubeScanUserCredentialsId)
    }

    onlyOnMaster {
        onlyOnRelease {
            stage('Add Tag to Git') {
                updateGitTag(technicalUserCredentialsId, projectVersion)
            }
        }
    }

    onlyOnDev {
        onlyOnSnapshot {
            stage('Publish to Nexus') {
                withMaven() {
                    sh "mvn deploy -P INSTNJ-SNAPSHOT -DskipTests"
                }
            }
        }
    }

    onlyOnMaster {
        onlyOnRelease {
            stage('Publish to Nexus') {
                withMaven() {
                    sh "mvn deploy -P INSTNJ-RELEASE -DskipTests"
                }
            }
        }
    }

//    onlyOnDev {
//        stage('Update Project version') {
//            updateMavenPatchVersion(technicalUserCredentialsId)
//        }
//    }
}
