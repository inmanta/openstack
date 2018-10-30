pipeline {
    agent any

    withCredentials([usernamePassword(credentialsId: 'openstack-super-user', passwordVariable: 'os_password', usernameVariable: 'os_username')]) {
        environment {
            OS_AUTH_URL=credentials('openstack_url')
            OS_USERNAME=os_username
            OS_PASSWORD=os_password
            OS_PROJECT_NAME='admin'
            INMANTA_MODULE_REPO='https://github.com/inmanta'
            INMANTA_TEST_ENV="${env.WORKSPACE}/env"
        } 
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