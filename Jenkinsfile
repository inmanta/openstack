pipeline {
    agent any

    environment {
        OS_AUTH_URL=credentials('openstack_url')
        OS_PROJECT_NAME='admin'
        INMANTA_MODULE_REPO='https://github.com/inmanta'
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
                withCredentials([usernamePassword(credentialsId: 'openstack-super-user', passwordVariable: 'OS_PASSWORD', usernameVariable: 'OS_USERNAME')]) {
                    sh 'rm -rf $INMANTA_TEST_ENV; python3 -m virtualenv $INMANTA_TEST_ENV; $INMANTA_TEST_ENV/bin/python3 -m pip install -U  inmanta pytest-inmanta; $INMANTA_TEST_ENV/bin/python3 -m pip install -r requirements.txt'
                    // fix for bug in pytest-inmanta where folder name is used as module name
                    sh "ln -s ${env.WORKSPACE} ${env.WORKSPACE}/openstack"
                    dir('openstack'){
                        sh '$INMANTA_TEST_ENV/bin/python3 -m pytest --junitxml=junit-{envname}.xml -vvv tests/test_dummy.py'
                    }
                }
            }
        }
    }
}