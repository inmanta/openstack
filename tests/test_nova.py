"""
    Copyright 2022 Inmanta

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
from typing import Optional, Tuple

import inmanta
import pytest
from inmanta.ast import ExplicitPluginException


def get_model(
    name: str,
    key: str,
    os_credentials,
    purged: Optional[bool] = False,
    flavor_constraints: Optional[Tuple[int, int]] = None,
) -> str:
    if flavor_constraints is None:
        flavor_constraints = (1, 0.5)

    return f"""
import unittest
import openstack
import ssh

os = std::OS(name="cirros", version=0.4, family=std::linux)

tenant = "{os_credentials.project_name}"
p = openstack::Provider(
    name="test",
    connection_url="{os_credentials.auth_url}",
    username="{os_credentials.username}",
    password="{os_credentials.password}",
    tenant=tenant,
    verify_cert={str(os_credentials.verify_cert).lower()}
)
key = ssh::Key(name="{name}", public_key="{key}")
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
net = openstack::Network(provider=p, project=project, name="{name}", purged={str(purged).lower()})
subnet = openstack::Subnet(
    provider=p,
    project=project,
    network=net,
    dhcp=true,
    name="{name}",
    network_address="10.255.255.0/24",
    purged={str(purged).lower()},
)
security_group = openstack::SecurityGroup(provider=p, project=project, name="{name}")
openstack::IPrule(group=security_group, direction="egress", ip_protocol="all", remote_prefix="0.0.0.0/0")
openstack::IPrule(group=security_group, direction="ingress", ip_protocol="icmp", remote_prefix="0.0.0.0/0")
openstack::IPrule(group=security_group, direction="ingress", ip_protocol="tcp", port=22, remote_prefix="0.0.0.0/0")
vm = openstack::Host(
    provider=p,
    project=project,
    key_pair=key,
    name="{name}",
    os=os,
    image=openstack::find_image(p, os),
    flavor=openstack::find_flavor(p, {", ".join(map(str, flavor_constraints))}),
    user_data="",
    subnet=subnet,
    security_groups=[security_group],
    purged={str(purged).lower()},
)
    """


def test_boot_vm(
    project, keystone_multi, nova_multi, neutron_multi, os_credentials_multi
):
    name = "inmanta-unit-test"

    project_id = keystone_multi.projects.find(name=os_credentials_multi.project_name).id

    key = (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCsiYV4Cr2lD56bkVabAs2i0WyGSjJbuNHP6IDf8Ru3Pg7DJkz0JaBmETHNjIs+yQ98DNkwH9gZX0"
        "gfrSgX0YfA/PwTatdPf44dwuwWy+cjS2FAqGKdLzNVwLfO5gf74nit4NwATyzakoojHn7YVGnd9ScWfwFNd5jQ6kcLZDq/1w== "
        "bart@wolf.inmanta.com"
    )

    project.add_fact(
        "openstack::Host[dnetcloud,name=%s]" % name, "ip_address", "10.1.1.1"
    )
    project.compile(get_model(name, key, os_credentials_multi))

    n1 = project.get_resource("openstack::Network", name=name)
    ctx = project.deploy(n1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    s1 = project.get_resource("openstack::Subnet", name=name)
    ctx = project.deploy(s1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    sg1 = project.get_resource("openstack::SecurityGroup", name=name)
    ctx = project.deploy(sg1)
    assert ctx.status == inmanta.const.ResourceState.deployed
    assert neutron_multi.list_security_groups(project_id=project_id, name=name)

    h1 = project.get_resource("openstack::VirtualMachine", name=name)
    ctx = project.deploy(h1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    server = nova_multi.servers.find(name=name)
    assert server is not None

    # Get id security group
    security_groups = neutron_multi.list_security_groups(
        project_id=project_id, name=name
    )["security_groups"]
    assert len(security_groups) == 1
    sec_group = security_groups[0]
    assert sec_group["name"] == name
    # A rule with protocol=all expands to two rules
    assert len(sec_group["security_group_rules"]) == 4
    sec_group_id = sec_group["id"]

    # Verify security group is attached to VM
    attached_security_groups = nova_multi.servers.list_security_group(server=server.id)
    timeout = 180
    # Wait until the security group is attached to the VirtualMachine
    while len(attached_security_groups) == 0:
        if timeout == 0:
            raise Exception("Security group didn't get attached to VM")
        time.sleep(1)
        timeout -= 1
        attached_security_groups = nova_multi.servers.list_security_group(
            server=server.id
        )
    assert len(attached_security_groups) == 1
    assert attached_security_groups[0].id == sec_group_id

    # cleanup
    project.compile(get_model(name, key, os_credentials_multi, purged=True))

    h1 = project.get_resource("openstack::VirtualMachine", name=name)
    ctx = project.deploy(h1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    server = None
    try:
        count = 0
        while count < 10:
            time.sleep(1)
            server = nova_multi.servers.find(name=name)
            count += 1

        assert False, "VM should be gone in 10 seconds"
    except Exception:
        pass

    count = 0
    while server is not None and count < 60:
        ports = neutron_multi.list_ports(device_id=server.id)
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

    try:
        server = nova_multi.servers.find(name=name)
        server.delete()
    except Exception:
        pass

    try:
        nova_multi.keypairs.find(name=name).delete()
    except Exception:
        pass

    networks = neutron_multi.list_subnets(name=s1.name)["subnets"]
    if len(networks) > 0:
        for network in networks:
            neutron_multi.delete_subnet(network["id"])

    networks = neutron_multi.list_networks(name=n1.name)["networks"]
    if len(networks) > 0:
        for network in networks:
            neutron_multi.delete_network(network["id"])

    neutron_multi.delete_security_group(sec_group_id)


def test_59_find_flavor_exception(project, keystone, nova, os_credentials) -> None:
    name = "inmanta-unit-test"
    key = (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCsiYV4Cr2lD56bkVabAs2i0WyGSjJbuNHP6IDf8Ru3Pg7DJkz0JaBmETHNjIs+yQ98DNkwH9gZX0"
        "gfrSgX0YfA/PwTatdPf44dwuwWy+cjS2FAqGKdLzNVwLfO5gf74nit4NwATyzakoojHn7YVGnd9ScWfwFNd5jQ6kcLZDq/1w== "
        "bart@wolf.inmanta.com"
    )
    cpus: int = 4096
    ram: int = 4096
    with pytest.raises(
        ExplicitPluginException,
        match=f"Couldn't find a flavor with at least {cpus} unpinned CPUs and {ram} Gigabytes of RAM",
    ):
        project.compile(
            get_model(name, key, os_credentials, flavor_constraints=(cpus, ram))
        )
