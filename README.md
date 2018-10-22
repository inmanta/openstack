# Openstack Module

## Running tests

1. On the test  openstack, create a `cirros` image with `os_distro = cirros` and `os.version = 0.4` (found: [here](http://download.cirros-cloud.net/0.4.0/cirros-0.4.0-x86_64-disk.img))

1. Setup a virtual env 

```bash
mkvirtualenv inmanta-test -p python3
pip install pytest-inmanta pytest-progress
pip install -r requirements.txt

mkdir /tmp/env
export INMANTA_TEST_ENV=/tmp/env
```

1. Setup parameters

```bash
export INMANTA_MODULE_REPO=git@github.com:inmanta/

export OS_AUTH_URL=
export OS_USERNAME=
export OS_PASSWORD=
export OS_PROJECT_NAME=
```

1. Run tests

```bash
py.test --show-progress tests
```
