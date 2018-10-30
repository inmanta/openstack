pipeline {
    agent any

    environment {
        OS_AUTH_URL='http://192.168.2.30:5000/v3'
        OS_USERNAME=
        OS_PASSWORD=
        OS_PROJECT_NAME='admin'
        INMANTA_MODULE_REPO='https://github.com/inmanta'
        INMANTA_TEST_ENV="${env.WORKSPACE}/env"
    }

    stages {
        stage('Test') {
            steps {
                sh 'mkdir -p $INMANTA_TEST_ENV'
                echo 'Testing..'
                sh 'tox'
            }
        }
    }
}