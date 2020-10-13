# Openstack Module

## Running tests

1. On the test  openstack, create a `cirros` image with `os_distro = cirros` and `os.version = 0.4` (found: [here](http://download.cirros-cloud.net/0.4.0/cirros-0.4.0-x86_64-disk.img))

2. Setup a virtual env

```bash
mkvirtualenv inmanta-test -p python3
pip install pytest-inmanta pytest-progress
pip install -r requirements.txt

mkdir /tmp/env
export INMANTA_TEST_ENV=/tmp/env
```

3a. Setup parameter (run against existing openstack instance)

```bash
export INMANTA_MODULE_REPO=git@github.com:inmanta/

# Connection details of packstack
export OS_AUTH_URL=
# Auth URL for endpoint serving a self-signed certificate
export OS_AUTH_URL_SS=
export OS_USERNAME=
export OS_PASSWORD=
export OS_PROJECT_NAME=
```

3b. Setup parameter (Spin up packstack instance)

```bash
export INMANTA_MODULE_REPO=git@github.com:inmanta/

# Indicate that the test fixtures should spin up a packstack instance
export INMANTA_TEST_INFRA_SETUP=true
# Connection detail for openstack instance hosting the packstack instance
export INFRA_SETUP_OS_AUTH_URL=
export INFRA_SETUP_OS_USERNAME=
export INFRA_SETUP_OS_PASSWORD=
export INFRA_SETUP_OS_PROJECT_NAME=
# IP address of packstack instance after boot
export PACKSTACK_IP=
# ID of the network the packstack instance should be connected to
export PACKSTACK_NETWORK_ID=

# Connection details of packstack
export OS_AUTH_URL=
# Auth URL on packstack instance serving a self-signed certificate
export OS_AUTH_URL_SS=
export OS_USERNAME=
export OS_PASSWORD=
export OS_PROJECT_NAME=
```

4. Run tests

```bash
py.test --show-progress tests
```
