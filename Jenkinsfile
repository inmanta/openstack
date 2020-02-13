pipeline {
    agent any

    options{
        checkoutToSubdirectory('openstack')
        disableConcurrentBuilds()
    }

    environment {
        INMANTA_TEST_ENV="${env.WORKSPACE}/env"
        OS_USER_DOMAIN_NAME='Default'	
        OS_PROJECT_DOMAIN_ID='default'	
        OS_REGION_NAME='RegionOne'	
        OS_INTERFACE='public'	
        OS_IDENTITY_API_VERSION=3
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

        stage('Start packstack'){
            steps{
                script {
                    withCredentials([usernamePassword(credentialsId: 'jenkins_on_openstack', passwordVariable: 'OS_PASSWORD', usernameVariable: 'OS_USERNAME'),
                                 string(credentialsId: 'jenkins_on_openstack_url_node3', variable: 'OS_AUTH_URL')]) {
                        sh '''
                            export OS_PROJECT_NAME="${OS_USERNAME}"
                            rm -f server_id port_id
                            $INMANTA_TEST_ENV/bin/openstack server create --config-drive true --user-data ./openstack/ci/user_data --image packstack-snapshot --flavor c4m16d20 --network 14376e55-8447-4aa9-9b35-b8f922eadbd6 -c id -f value --wait packstack > server_id
                            server_id=$(cat server_id)
                            $INMANTA_TEST_ENV/bin/openstack port list --server ${server_id} -c id -f value > port_id
                            port_id=$(cat port_id)
                            $INMANTA_TEST_ENV/bin/openstack port set --no-security-group ${port_id}
                            $INMANTA_TEST_ENV/bin/openstack port set --disable-port-security ${port_id}

                            echo "Wait until Packstack is up..."

                            exitcode=1
                            counter=0
                            while [ ${exitcode} -ne 0 ]; do
                              if [ ${counter} -ge 300 ]; then
                                echo "Timeout"
                                exit 1
                              fi

                              for port in 8774 5000 9292 9696 8778 8776; do
                                echo "Checking if http://192.168.26.18:${port} is up"
                                set +e
                                exitcode=$(curl --fail http://192.168.26.18:${port})
                                set -e
                                if [ ${exitcode} -ne 0 ]; then
                                  echo "Not available"
                                  sleep 5
                                  break
                                else
                                  echo "OK"
                                fi
                              done

                              counter=$((${counter}+1))
                            done
                        '''
                    }
                }
            }
        }

        stage('linting') {
            steps {
                script {
                    sh '''
                        ${WORKSPACE}/env/bin/flake8 ${WORKSPACE}/plugins ${WORKSPACE}/tests
                    '''
                }
            }
        }

        stage('tests') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'packstack-super-user', passwordVariable: 'OS_PASSWORD', usernameVariable: 'OS_USERNAME'),
                                 string(credentialsId: 'packstack_url', variable: 'OS_AUTH_URL')]) {
                    // fix for bug in pytest-inmanta where folder name is used as module name
                    dir('openstack'){
                        sh '''
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
        always {
            script {
                withCredentials([usernamePassword(credentialsId: 'jenkins_on_openstack', passwordVariable: 'OS_PASSWORD', usernameVariable: 'OS_USERNAME'),
                                 string(credentialsId: 'jenkins_on_openstack_url_node3', variable: 'OS_AUTH_URL')]) {
                    sh '''
                        if [ -e server_id ]; then
                            export OS_PROJECT_NAME="${OS_USERNAME}"
                            $INMANTA_TEST_ENV/bin/openstack server delete $(cat server_id)
                        fi
                    '''
                }
            }
        }
    }
}
