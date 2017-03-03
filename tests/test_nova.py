"""
    Copyright 2017 Inmanta

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    Contact: code@inmanta.com
"""

import os
import time

import inmanta
import pytest


def print_ctx(ctx):
    print(ctx._changes)
    for l in ctx.logs:
        print(l._data)
        if "traceback" in l._data["kwargs"]:
            print(l._data["kwargs"]["traceback"])


def find_small_flavor(nova):
    smallest = None
    for flavor in nova.flavors.list():
        if smallest is None:
            smallest = flavor
        elif flavor.ram < smallest.ram:
            smallest = flavor

    return smallest


def test_boot_vm(project, keystone, nova, neutron):
    name = "inmanta-unit-test"
    images = [n for n in nova.images.list() if "cirros" in n.name]
    if len(images) == 0:
        raise Exception("No image with name 'cirros' in its name available")
    image = images[0].id

    flavor = find_small_flavor(nova).name

    project.add_fact("openstack::Host[dnetcloud,name=%s]" % name, "ip_address", "10.1.1.1")
    project.compile("""
import unittest
import openstack
import ssh

tenant = std::get_env("OS_PROJECT_NAME")
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
key = ssh::Key(name="%(name)s", public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCsiYV4Cr2lD56bkVabAs2i0WyGSjJbuNHP6IDf8Ru3Pg7DJkz0JaBmETHNjIs+yQ98DNkwH9gZX0gfrSgX0YfA/PwTatdPf44dwuwWy+cjS2FAqGKdLzNVwLfO5gf74nit4NwATyzakoojHn7YVGnd9ScWfwFNd5jQ6kcLZDq/1w== bart@wolf.inmanta.com")
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
net = openstack::Network(provider=p, project=project, name="%(name)s")
subnet = openstack::Subnet(provider=p, project=project, network=net, dhcp=true, name="%(name)s",
                           network_address="10.255.255.0/24")
vm = openstack::Host(provider=p, project=project, key_pair=key, name="%(name)s", os=std::linux,
                     image="%(image)s", flavor="%(flavor)s", user_data="", subnet=subnet)
        """ % {"name": name, "image": image, "flavor": flavor})

    n1 = project.get_resource("openstack::Network", name=name)
    ctx = project.deploy(n1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    s1 = project.get_resource("openstack::Subnet", name=name)
    ctx = project.deploy(s1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    h1 = project.get_resource("openstack::Host", name=name)
    ctx = project.deploy(h1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    server = nova.servers.find(name=name)
    assert server is not None

    # cleanup
    project.compile("""
import unittest
import openstack
import ssh

tenant = std::get_env("OS_PROJECT_NAME")
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
key = ssh::Key(name="%(name)s", public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCsiYV4Cr2lD56bkVabAs2i0WyGSjJbuNHP6IDf8Ru3Pg7DJkz0JaBmETHNjIs+yQ98DNkwH9gZX0gfrSgX0YfA/PwTatdPf44dwuwWy+cjS2FAqGKdLzNVwLfO5gf74nit4NwATyzakoojHn7YVGnd9ScWfwFNd5jQ6kcLZDq/1w== bart@wolf.inmanta.com")

project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
net = openstack::Network(provider=p, project=project, name="%(name)s", purged=true)
subnet = openstack::Subnet(provider=p, project=project, network=net, dhcp=true, name="%(name)s",
                           network_address="10.255.255.0/24", purged=true)
vm = openstack::Host(provider=p, project=project, key_pair=key, name="%(name)s", os=std::linux,
                     image="%(image)s", flavor="%(flavor)s", user_data="", subnet=subnet, purged=true)
        """ % {"name": name, "image": image, "flavor": flavor})

    h1 = project.get_resource("openstack::Host", name=name)
    ctx = project.deploy(h1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    try:
        count = 0
        while count < 10:
            time.sleep(1)
            server = nova.servers.find(name=name)
            count += 1

        assert False, "VM should be gone in 10 seconds"
    except Exception:
        pass

    s1 = project.get_resource("openstack::Subnet", name=name)
    ctx = project.deploy(s1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    n1 = project.get_resource("openstack::Network", name=name)
    ctx = project.deploy(n1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    try:
        server = nova.servers.find(name=name)
        server.delete()
    except Exception:
        pass

    try:
        nova.keypairs.find(name=name).delete()
    except Exception:
        pass

    networks = neutron.list_subnets(name=s1.name)["subnets"]
    if len(networks) > 0:
        for network in networks:
            neutron.delete_subnet(network["id"])

    networks = neutron.list_networks(name=n1.name)["networks"]
    if len(networks) > 0:
        for network in networks:
            neutron.delete_network(network["id"])

