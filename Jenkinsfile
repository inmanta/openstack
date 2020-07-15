pipeline {
    agent any

    options{
        checkoutToSubdirectory('openstack')
        disableConcurrentBuilds()
        lock('Packstack')
    }

    environment {
        INMANTA_TEST_ENV="${env.WORKSPACE}/env"
        INMANTA_TEST_INFRA_SETUP='true'
    }

    triggers {
        pollSCM('* * * * *')
        cron("H H(2-5) * * *")
    }

    stages {
        stage('setup venv') {
            steps {
                script {
                    sh '''
                        rm -rf $INMANTA_TEST_ENV
                        python3 -m venv $INMANTA_TEST_ENV
                        $INMANTA_TEST_ENV/bin/python3 -m pip install -U  inmanta pytest-inmanta
                        $INMANTA_TEST_ENV/bin/python3 -m pip install -r openstack/requirements.txt
                        $INMANTA_TEST_ENV/bin/python3 -m pip install -r openstack/requirements.dev.txt
                        $INMANTA_TEST_ENV/bin/python3 -m pip install python-openstackclient
                    '''
                }
            }
        }

        stage('linting') {
            steps {
                script {
                    sh '''
                        ${WORKSPACE}/env/bin/flake8 ${WORKSPACE}/openstack/plugins ${WORKSPACE}/openstack/tests
                    '''
                }
            }
        }

        stage('tests') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'jenkins_on_openstack',
                        passwordVariable: 'INFRA_SETUP_OS_PASSWORD',
                        usernameVariable: 'INFRA_SETUP_OS_USERNAME',
                    ),
                    string(credentialsId: 'jenkins_on_openstack_url_node3', variable: 'INFRA_SETUP_OS_AUTH_URL'),
                    usernamePassword(
                        credentialsId: 'packstack-super-user', passwordVariable: 'OS_PASSWORD', usernameVariable: 'OS_USERNAME'
                    ),
                    string(credentialsId: 'packstack_url', variable: 'OS_AUTH_URL')
                ]) {
                    // fix for bug in pytest-inmanta where folder name is used as module name
                    dir('openstack'){
                        sh '''
                            export INFRA_SETUP_OS_PROJECT_NAME="${PACKSTACK_OS_USERNAME}"
                            export OS_PROJECT_NAME="${OS_USERNAME}"
                            $INMANTA_TEST_ENV/bin/python3 -m pytest --junitxml=junit.xml -vvv tests
                        '''
                    }
                }
            }
        }
    }

    post {
        success{
            junit 'openstack/junit.xml'
        }
    }
}
