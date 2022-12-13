# Openstack Module

The openstack module provides support for managing various resources on OpenStack, including virtual
machines, networks, routers, ...

## How to use it

This guide explains how to start virtual machines on OpenStack.More examples can be found in the `examples` folder of this repo.

### Prerequisites

This tutorial requires you to have an account on an OpenStack. The example below loads the required
credentials from environment variables, just like the OpenStack command line tools. Additionally,
the following parameters are also required:

- **ssh_public_key** : Your public ssh key (the key itself, not the name of the file it is in)
- **network_name**   : The name of the Openstack network to connect the VM to
- **subnet_name**    : The name of the Openstack subnet to connect the VM to
- **network_address**: The network address of the subnet above
- **flavor_name**    : The name of the Openstack flavor to create the VM from
- **image_id**       : The ID of the Openstack image to boot the VM from
- **os**             : The OS of the image

### Creating machines

The following model creates a new virtual machine. The parameters in the list above are exposed as variables at the start of the code snippet.

```inmanta
import openstack
import ssh
import redhat
import ubuntu

## Edit this parameters
image_id = ""
network_name = ""
subnet_name = ""
network_address = ""

flavor_name = ""
ssh_public_key=""

# change OS parameter to match the actual image. If an OS is not modelled in an existing module,
# std::linux can be used for example. However, other modules might not have support for a
# generic os definition such as std::linux
os = redhat::fedora23
## End edit

# register ssh key
ssh_key = ssh::Key(name="mykey", public_key=ssh_public_key)

# Define the OpenStack provider to use
provider = openstack::Provider(name="iaas_openstack", connection_url=std::get_env("OS_AUTH_URL"),
                               username=std::get_env("OS_USERNAME"),
                               password=std::get_env("OS_PASSWORD"),
                               tenant=std::get_env("OS_PROJECT_NAME"))

# Define the project/tenant to boot the VM in, but do not let inmanta manage it
project = openstack::Project(provider=provider, name=provider.tenant, description="", enabled=true,
                             managed=false)

# Define the network objects to connect the virtual machine to but again, do not manage them
net = openstack::Network(provider=provider, project=project, name=network_name, managed=false)
subnet = openstack::Subnet(provider=provider, project=project, network=net, dhcp=true, managed=false,
                           name=subnet_name, network_address=network_address)

# Define the virtual machine
vm = openstack::Host(provider=provider, project=project, key_pair=ssh_key, name="testhost",
                     image=image_id, os=os, flavor=flavor_name, user_data="", subnet=subnet)
```

### Getting the agent on the machine

The user_data attribute of the :inmanta:entity:`openstack::VirtualMachine` entity can inject a shell script that is executed
at first boot of the virtual machine (through cloud-init). Below is an example script to install
the inmanta agent (from RPM) and let it connect back to the management server.

```bash
#!/bin/bash

hostname {{ name }}

curl -1sLf \
  'https://packages.inmanta.com/public/oss-stable/setup.rpm.sh' \
  | sudo -E bash

dnf install -y inmanta-oss-agent

cat > /etc/inmanta/agent.cfg <<EOF
[config]
heartbeat-interval = 60
fact-expire = 60
state-dir=/var/lib/inmanta
environment={{ env_id }}
agent-names=\$node-name
[agent_rest_transport]
port={{port}}
host={{env_server}}
EOF

systemctl start inmanta-agent
systemctl enable inmanta-agent

```

### Pushing resources to the machine

You can use adapters from std or other modules to manage resources on the machine. For example, we can create a config file in /tmp by adding the following lines to the model that created the virtual machine:

```inmanta
#put a file on the machine
std::ConfigFile(host = host1, path="/tmp/test", content="I did it!")
```

### Actual usage

Creating instances of `openstack::Host`, as shown above requires many parameters and relations,
creating a model that is hard to read. Often, these parameters are all the same within a single
model. This means that Inmanta can encapsulate this complexity.

In a larger model, a new `Host` type can encapsulate all settings that are the same for all hosts.
Additionally, an entity that represents the `infrastructure` can hold shared configuration such as
the provider, monitoring, shared networks, global parameters,...)

For example (`full source here <https://github.com/inmanta/openstack/tree/master/examples/openstackclean>`_)

Applied to the example above the main file is reduced to:

```inmanta
import mymodule
import ssh
import redhat
import ubuntu

## Edit this parameters
image_id = ""
network_name = ""
subnet_name = ""
network_address = ""

flavor_name = ""
ssh_public_key=""

# change OS parameter to match the actual image. If an OS is not modelled in an existing module,
# std::linux can be used for example. However, other modules might not have support for a
# generic os definition such as std::linux
os = redhat::fedora23
## End edit

# register ssh key
ssh_key = ssh::Key(name="mykey", public_key=ssh_public_key)

# create the cluster
cluster = mymodule::MyCluster(network_name=network_name, subnet_name=subnet_name,
                              image_id=image_id, flavor=flavor_name, key=ssh_key,
                              network_address=network_address, os=os)

# make a vm!
host1 = mymodule::MyHost(name="testhost", cluster=cluster)
```

With the following module:

```inmanta
import openstack
import ssh


entity MyCluster:
    """
        A cluster object that represents all shared config and infrastructure,
        including connecting to OpenStack.
    """
    string network_name
    string subnet_name
    string network_address
    string image_id
    string flavor
end

#input: the ssh key for all VMs
MyCluster.key [1] -- ssh::Key

#input: the OS for all VMs
MyCluster.os [1] -- std::OS

#internal: objects needed to construct hosts
MyCluster.provider [1] -- openstack::Provider
MyCluster.project [1] -- openstack::Project
MyCluster.net [1] -- openstack::Network
MyCluster.subnet [1] -- openstack::Subnet

implementation connection for MyCluster:
    # Define the OpenStack provider to use
    self.provider = openstack::Provider(name="iaas_openstack",
                                        connection_url=std::get_env("OS_AUTH_URL"),
                                        username=std::get_env("OS_USERNAME"),
                                        password=std::get_env("OS_PASSWORD"),
                                        tenant=std::get_env("OS_PROJECT_NAME"))

    # Define the project/tenant to boot the VM in, but do not let inmanta manage it
    self.project = openstack::Project(provider=self.provider, name=self.provider.tenant,
                                      description="", enabled=true, managed=false)

    # Define the network objects to connect the virtual machine to but again, do not manage them
    self.net = openstack::Network(provider=self.provider, project=self.project,
                                  name=self.network_name, managed=false)
    self.subnet = openstack::Subnet(provider=self.provider, project=self.project,
                                    network=self.net, dhcp=true, name=self.subnet_name,
                                    network_address=self.network_address, managed=false)
end

implement MyCluster using connection

#define our own host type
entity MyHost extends openstack::Host:
end

#input: the cluster object
MyCluster.hosts [0:] -- MyHost.cluster [1]

implementation myhost for MyHost:
    #wire up all config for agent injection
    env_name = std::environment_name()
    env_id = std::environment()
    env_server = std::environment_server()
    port = std::server_port()

    #wire up all config for vm creation
    self.provider = cluster.provider
    self.project = cluster.project
    self.image = cluster.image_id
    self.subnet = cluster.subnet
    self.user_data = std::template("mymodule/user_data.tmpl")
    self.key_pair = cluster.key
    self.os = cluster.os
    self.flavor = cluster.flavor
end

# use our implemenation
# and also the catchall std::hostDefaults
# and the openstackVM implementation that sets the ip and create the eth0 port
implement MyHost using myhost, std::hostDefaults, openstack::openstackVM, openstack::eth0Port
```

If this were not an example, we would make the following changes:

- hardcode the ``image_id`` and ``os`` (and perhaps ``flavor``) into the defintion of ``myhost``.
- the parameters on top would be moved to either an lsm service or filled in directly into the constructor.
- use ``std::password`` to store passwords, to prevent accidential check-ins with passwords in the source

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

# Connection details of openstack instance
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
