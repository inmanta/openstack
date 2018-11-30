pipeline {
    agent any

    options{
        checkoutToSubdirectory('openstack')
        disableConcurrentBuilds()
    }

    environment {
        OS_AUTH_URL=credentials('openstack_url')
        OS_PROJECT_NAME='admin'
        INMANTA_MODULE_REPO='https://github.com/inmanta/'
        INMANTA_TEST_ENV="${env.WORKSPACE}/env"
        OS_IDENTITY_API_VERSION=3

    } 

    stages {
        stage('PreTest'){
            steps{
                sh 'curl $OS_AUTH_URL -v -m 2'
            }
        }
        stage('Test') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'openstack-super-user', passwordVariable: 'OS_PASSWORD', usernameVariable: 'OS_USERNAME')]) {
                    lock('Packstack') {
                        sh 'rm -rf $INMANTA_TEST_ENV; python3 -m virtualenv $INMANTA_TEST_ENV; $INMANTA_TEST_ENV/bin/python3 -m pip install -U  inmanta pytest-inmanta; $INMANTA_TEST_ENV/bin/python3 -m pip install -r openstack/requirements.txt'
                        // fix for bug in pytest-inmanta where folder name is used as module name
                        dir('openstack'){
                            sh "$INMANTA_TEST_ENV/bin/python3 -m pytest --junitxml=junit.xml -vvv tests --basetemp=${env.WORKSPACE}/tmp"
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            junit 'openstack/junit.xml'
        }
    }
}