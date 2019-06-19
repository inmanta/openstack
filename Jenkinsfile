pipeline {
    agent any

    options{
        checkoutToSubdirectory('openstack')
        disableConcurrentBuilds()
    }

    environment {
        OS_AUTH_URL=credentials('packstack_url')
        OS_PROJECT_NAME='admin'
        INMANTA_MODULE_REPO='https://github.com/inmanta/'
        INMANTA_TEST_ENV="${env.WORKSPACE}/env"
    } 

    stages {
        stage('PreTest'){
            steps{
                sh 'curl $OS_AUTH_URL -v -m 2'
            }
        }
        stage('Test') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'packstack-super-user', passwordVariable: 'OS_PASSWORD', usernameVariable: 'OS_USERNAME')]) {
                    sh 'rm -rf $INMANTA_TEST_ENV; python3 -m venv $INMANTA_TEST_ENV; $INMANTA_TEST_ENV/bin/python3 -m pip install -U  inmanta pytest-inmanta; $INMANTA_TEST_ENV/bin/python3 -m pip install -r openstack/requirements.txt'
                    // fix for bug in pytest-inmanta where folder name is used as module name
                    dir('openstack'){
                        sh '$INMANTA_TEST_ENV/bin/python3 -m pytest --junitxml=junit.xml -vvv tests/test_nova.py'
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