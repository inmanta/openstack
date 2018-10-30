pipeline {
    agent any

    environment {
        OS_AUTH_URL=credentials('openstack_url')
        OS_PROJECT_NAME='admin'
        INMANTA_MODULE_REPO='https://github.com/inmanta'
        INMANTA_TEST_ENV="${env.WORKSPACE}/env"
    } 

    stages {
        stage('Test') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'openstack-super-user', passwordVariable: 'OS_PASSWORD', usernameVariable: 'OS_USERNAME')]) {
                    sh 'mkdir -p $INMANTA_TEST_ENV'
                    echo 'Testing..'
                    sh 'tox'
                }
            }
        }
    }
}