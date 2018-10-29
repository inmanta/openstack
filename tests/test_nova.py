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
import time

import inmanta

import pytest
import os

import novaclient

def print_ctx(ctx):
    print(ctx._changes)
    for l in ctx.logs:
        print(l._data)
        if "traceback" in l._data["kwargs"]:
            print(l._data["kwargs"]["traceback"])



def make_model(project, osproject, name, cidr="10.255.255.0/24", purged=False):
    key = ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCsiYV4Cr2lD56bkVabAs2i0WyGSjJbuNHP6IDf8Ru3Pg7DJkz0JaBmETHNjIs+yQ98DNkwH9gZX0"
           "gfrSgX0YfA/PwTatdPf44dwuwWy+cjS2FAqGKdLzNVwLfO5gf74nit4NwATyzakoojHn7YVGnd9ScWfwFNd5jQ6kcLZDq/1w== "
           "bart@wolf.inmanta.com")

    project.compile("""
import unittest
import openstack
import ssh

os = std::OS(name="cirros", version=0.4, family=std::linux)

tenant = "%(project)s"
p = openstack::Provider(name="test", connection_url="%(auth_url)s", username="%(username)s",
                        password="%(password)s", tenant=tenant, project_domain_name="%(domain)s", user_domain_name="%(domain)s")
key = ssh::Key(name="%(name)s", public_key="%(key)s")
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
net = openstack::Network(provider=p, project=project, name="%(name)s", purged=%(purged)s)
subnet = openstack::Subnet(provider=p, project=project, network=net, dhcp=true, name="%(name)s",
                        network_address="%(cidr)s", purged=%(purged)s)
vm = openstack::Host(provider=p, project=project, key_pair=key, name="%(name)s", os=os,
                    image=openstack::find_image(p, os), flavor=openstack::find_flavor(p, 1, 0.5), user_data="", subnet=subnet, purged=%(purged)s)
        """ % {"name": name, 
                "key": key, 
                "project": osproject._tenant, 
                "auth_url": osproject._auth_url,
                "username": osproject._username,
                "password": osproject._password,
                "domain":osproject._domain,
                "purged": "true" if purged else "false",
                "cidr": cidr
                }) 

def deploy_vm(project, osproject, name, cidr="10.255.255.0/24"):
    make_model(project, osproject, name, cidr)
    n1 = project.get_resource("openstack::Network", name=name)
    ctx = project.deploy(n1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    s1 = project.get_resource("openstack::Subnet", name=name)
    ctx = project.deploy(s1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    h1 = project.get_resource("openstack::VirtualMachine", name=name)
    ctx = project.deploy(h1)
    assert ctx.status == inmanta.const.ResourceState.deployed


def destroy_vm(project, osproject, name, cidr="10.255.255.0/24"):
    make_model(project, osproject, name, cidr, True)

    h1 = project.get_resource("openstack::VirtualMachine", name=name)
    ctx = project.deploy(h1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    server = None
    try:
        count = 0
        while count < 10:
            time.sleep(1)
            server = osproject.nova.servers.find(name=name)
            count += 1

        assert False, "VM should be gone in 10 seconds"
    except Exception:
        pass

    count = 0
    while server is not None and count < 60:
        ports = osproject.neutron.list_ports(device_id=server.id)
        if len(ports["ports"]) > 0:
            time.sleep(1)
            count += 1
        else:
            server = None

    assert server is None, "Waiting for VM delete timeout"

    s1 = project.get_resource("openstack::Subnet", name=name)
    ctx = project.deploy(s1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    n1 = project.get_resource("openstack::Network", name=name)
    ctx = project.deploy(n1)
    assert ctx.status == inmanta.const.ResourceState.deployed

def test_boot_vm(project, openstack):
    osproject = openstack.get_project("test_boot_vm")

    name = "inmanta-unit-test"
   
    project.add_fact("openstack::Host[dnetcloud,name=%s]" % name, "ip_address", "10.1.1.1")

    deploy_vm(project, osproject, name)
  

    server = osproject.nova.servers.find(name=name)
    assert server is not None
    
    destroy_vm(project, osproject, name)

@pytest.mark.skipif("D2_OS_DOMAIN" not in os.environ,
                    reason="set paramaters D2_OS_USERNAME D2_OS_PASSWORD D2_OS_PROJECT_NAME and D2_OS_DOMAIN to have multi domain tests")
def test_boot_vm_two_domains(project, openstack, openstackD2):
    name = "inmanta-unit-test"


    osproject = openstack.get_project("test_boot_vm")
    d2osproject = openstackD2.get_project("test_boot_vm")


    def exists(one, two):
        try:
            server = osproject.nova.servers.find(name=name)
            assert (server is not None) == one
            print("one exists")
        except novaclient.exceptions.NotFound:
            assert not one
            print("one does not ")


        try:
            server2 = d2osproject.nova.servers.find(name=name)
            assert (server2 is not None) == two
            print("two exists")
        except novaclient.exceptions.NotFound:
            assert not two
            print("two does not ")

    
    exists(False, False)
    deploy_vm(project, osproject, name)
    exists(True, False)
    deploy_vm(project, d2osproject, name, cidr="10.200.255.0/24")

    exists(True, True)

    destroy_vm(project, osproject, name)

    exists(False, True)

    destroy_vm(project, d2osproject, name, cidr="10.200.255.0/24")
    exists(False, False)
