#!/usr/bin/env groovy

projectName = ''
projectVersion = ''

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
        cleanMavenArtifacts()
    }

    stage('Compile') {
        compileMavenArtifacts()
    }

    stage('Tests') {
        testMavenArtifacts()
    }

    stage('Package') {
        buildMavenArtifacts()
    }

//    stage('Nexus IQ analysis') {
//        dir('application') {
//            qualityAnalysisNexusIQ(technicalUserCredentialsId)
//        }
//    }

//    stage('SonarQube analysis') {
//        qualityAnalysisSonarQube()
//    }

    onlyOnMaster {
        onlyOnRelease {
            stage('Add Tag to Git') {
                updateGitTag(projectVersion)
            }
        }
    }

    stage('Package & Publish to Nexus') {
        deployMavenArtifacts()
    }
}
