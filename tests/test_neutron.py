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
import uuid
from dataclasses import dataclass
from typing import Dict, Optional

import inmanta
import pytest


def test_net(project, neutron):
    try:
        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="test_net", project=project, external=true)
            """
        )

        n1 = project.deploy_resource("openstack::Network", name="test_net")

        networks = neutron.list_networks(name=n1.name)["networks"]
        assert len(networks) == 1

        assert networks[0]["router:external"]

        ctx = project.deploy(n1)
        assert ctx.status == inmanta.const.ResourceState.deployed

        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="test_net", project=project, purged=true)
            """
        )

        n1 = project.get_resource("openstack::Network", name="test_net")
        ctx = project.deploy(n1)
        assert ctx.status == inmanta.const.ResourceState.deployed

        networks = neutron.list_networks(name=n1.name)["networks"]
        assert len(networks) == 0

    finally:
        # cleanup
        networks = neutron.list_networks(name=n1.name)["networks"]
        if len(networks) > 0:
            for network in networks:
                neutron.delete_network(network["id"])


def test_subnet(project, neutron):
    name = "inmanta_unit_test"
    try:
        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="%(name)s", project=project)
    subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="%(name)s",
                               network_address="10.255.255.0/24", dns_servers=["8.8.8.8", "8.8.4.4"])
            """
            % {"name": name}
        )

        net = project.deploy_resource("openstack::Network")
        subnet = project.deploy_resource("openstack::Subnet")

        subnets = neutron.list_subnets(name=subnet.name)["subnets"]
        assert len(subnets) == 1
        assert len(neutron.list_networks(name=net.name)["networks"]) == 1

        os_subnet = subnets[0]
        assert len(os_subnet["dns_nameservers"]) == 2
        assert os_subnet["gateway_ip"] == "10.255.255.1"

        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="%(name)s", project=project, purged=true)
    subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="%(name)s",
                               network_address="10.255.255.0/24", purged=true)
            """
            % {"name": name}
        )

        net = project.deploy_resource("openstack::Network")
        subnet = project.deploy_resource("openstack::Subnet")

        assert len(neutron.list_subnets(name=subnet.name)["subnets"]) == 0
        assert len(neutron.list_networks(name=net.name)["networks"]) == 0

    finally:
        # cleanup
        networks = neutron.list_subnets(name=name)["subnets"]
        if len(networks) > 0:
            for network in networks:
                neutron.delete_subnet(network["id"])

        networks = neutron.list_networks(name=name)["networks"]
        if len(networks) > 0:
            for network in networks:
                neutron.delete_network(network["id"])


def test_router(project, neutron):
    name = "inmanta_unit_test"

    external = None
    for network in neutron.list_networks()["networks"]:
        if network["router:external"]:
            external = network

    assert external is not None, "This test requires an external network to be defined."

    project.compile(
        """
import unittest
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)

ext = openstack::Network(provider=p, name="%(external)s", project=project, managed=false)
router = openstack::Router(provider=p, project=project, name="%(name)s", ext_gateway=ext, admin_state="up")

n = openstack::Network(provider=p, name="%(name)s", project=project)
subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="%(name)s",
                           network_address="10.255.255.0/24")
router.subnets = subnet
        """
        % {"external": external["name"], "name": name}
    )

    net = project.deploy_resource("openstack::Network")
    subnet = project.deploy_resource("openstack::Subnet")
    project.deploy_resource("openstack::Router")

    routers = neutron.list_routers(name=name)["routers"]
    assert len(routers) == 1
    assert len(neutron.list_networks(name=net.name)["networks"]) == 1
    assert len(neutron.list_subnets(name=subnet.name)["subnets"]) == 1

    ports = neutron.list_ports(device_id=routers[0]["id"])["ports"]
    assert len(ports) == 2

    project.compile(
        """
import unittest
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)

ext = openstack::Network(provider=p, name="%(external)s", project=project, managed=false)
router = openstack::Router(provider=p, project=project, name="%(name)s", ext_gateway=ext, admin_state="up", purged=true)

n = openstack::Network(provider=p, name="%(name)s", project=project, purged=true)
subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="%(name)s",
                           network_address="10.255.255.0/24", purged=true)
router.subnets = subnet
        """
        % {"external": external["name"], "name": name}
    )

    project.deploy_resource("openstack::Router")

    routers = neutron.list_routers(name=name)["routers"]
    assert len(routers) == 0

    net = project.deploy_resource("openstack::Network")
    subnet = project.deploy_resource("openstack::Subnet")
    assert len(neutron.list_subnets(name=subnet.name)["subnets"]) == 0
    assert len(neutron.list_networks(name=net.name)["networks"]) == 0

    routers = neutron.list_routers(name=name)["routers"]
    if len(routers) > 0:
        for router in routers:
            neutron.delete_router(router["id"])

    networks = neutron.list_subnets(name=name)["subnets"]
    if len(networks) > 0:
        for network in networks:
            neutron.delete_subnet(network["id"])

    networks = neutron.list_networks(name=name)["networks"]
    if len(networks) > 0:
        for network in networks:
            neutron.delete_network(network["id"])


def test_router_port(project, neutron):
    name = "inmanta_unit_test"

    external = None
    for network in neutron.list_networks()["networks"]:
        if network["router:external"]:
            external = network

    assert external is not None, "This test requires an external network to be defined."

    project.compile(
        """
import unittest
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)

ext = openstack::Network(provider=p, name="%(external)s", project=project, managed=false)
router = openstack::Router(provider=p, project=project, name="%(name)s", ext_gateway=ext, admin_state="up")

n = openstack::Network(provider=p, name="%(name)s", project=project)
subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="%(name)s",
                           network_address="10.255.255.0/24")

openstack::RouterPort(provider=p, project=project, name="%(name)s", router=router, subnet=subnet, address="10.255.255.200")
        """
        % {"external": external["name"], "name": name}
    )

    net = project.deploy_resource("openstack::Network")
    subnet = project.deploy_resource("openstack::Subnet")
    project.deploy_resource("openstack::Router")
    project.deploy_resource("openstack::RouterPort")

    routers = neutron.list_routers(name=name)["routers"]
    assert len(routers) == 1
    assert len(neutron.list_networks(name=net.name)["networks"]) == 1
    assert len(neutron.list_subnets(name=subnet.name)["subnets"]) == 1

    ports = neutron.list_ports(device_id=routers[0]["id"])["ports"]
    assert len(ports) == 2

    # remove
    project.compile(
        """
import unittest
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)

ext = openstack::Network(provider=p, name="%(external)s", project=project, managed=false)
router = openstack::Router(provider=p, project=project, name="%(name)s", ext_gateway=ext, admin_state="up", purged=true)

n = openstack::Network(provider=p, name="%(name)s", project=project, purged=true)
subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="%(name)s", purged=true,
                           network_address="10.255.255.0/24")

openstack::RouterPort(provider=p, project=project, name="%(name)s", router=router, subnet=subnet, address="10.255.255.200",
                      purged=true)
        """
        % {"external": external["name"], "name": name}
    )

    project.deploy_resource("openstack::RouterPort")
    project.deploy_resource("openstack::Router")
    subnet = project.deploy_resource("openstack::Subnet")
    net = project.deploy_resource("openstack::Network")

    routers = neutron.list_routers(name=name)["routers"]
    assert len(routers) == 0
    assert len(neutron.list_networks(name=net.name)["networks"]) == 0
    assert len(neutron.list_subnets(name=subnet.name)["subnets"]) == 0


def test_update_rules_in_security_group(project, openstack, neutron):
    os_project = openstack.get_project("test")
    resource_name_sec_group1 = os_project.get_resource_name("sec_group1")
    resource_name_sec_group2 = os_project.get_resource_name("sec_group2")
    resource_name_sec_group3 = os_project.get_resource_name("sec_group3")

    project.compile(
        f"""
import unittest
import openstack

tenant = "{os_project._tenant}"
p = openstack::Provider(
            name="test",
            connection_url="{os_project._auth_url}",
            username="{os_project._username}",
            password="{os_project._password}",
            tenant=tenant)
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)

sg_base = openstack::SecurityGroup(provider=p, project=project, name="{resource_name_sec_group1}", description="test")
openstack::IPrule(
            group=sg_base,
            direction="ingress",
            ip_protocol="tcp",
            port_min=200,
            port_max=201,
            remote_prefix="0.0.0.0/0"
)
openstack::IPrule(
            group=sg_base,
            direction="ingress",
            ip_protocol="tcp",
            port_min=300,
            port_max=301,
            remote_prefix="0.0.0.0/0"
)
openstack::IPrule(
            group=sg_base,
            direction="ingress",
            ip_protocol="tcp",
            port_min=400,
            port_max=401,
            remote_prefix="0.0.0.0/0"
)
openstack::IPrule(
            group=sg_base,
            direction="ingress",
            ip_protocol="tcp",
            port_min=500,
            port_max=501,
            remote_prefix="0.0.0.0/0"
)
openstack::GroupRule(
            group=sg_base,
            direction="ingress",
            ip_protocol="tcp",
            port=222,
            remote_group=sg_base2
)

sg_base2 = openstack::SecurityGroup(provider=p, project=project, name="{resource_name_sec_group2}", description="test")
openstack::IPrule(
            group=sg_base2,
            direction="ingress",
            ip_protocol="tcp",
            port=8080,
            remote_prefix="0.0.0.0/0"
)
        """
    )

    @dataclass(frozen=True)
    class Rule:
        direction: str
        protocol: str
        port_range_min: int
        port_range_max: int
        remote_ip_prefix: Optional[str]
        remote_group_id: Optional[uuid.UUID]

        @classmethod
        def from_dict(cls, dct: Dict):
            return Rule(
                direction=dct["direction"],
                protocol=dct["protocol"],
                port_range_min=dct["port_range_min"],
                port_range_max=dct["port_range_max"],
                remote_ip_prefix=dct["remote_ip_prefix"],
                remote_group_id=dct["remote_group_id"],
            )

    project.deploy_resource("openstack::SecurityGroup", name=resource_name_sec_group2)
    project.deploy_resource("openstack::SecurityGroup", name=resource_name_sec_group1)
    sgs = neutron.list_security_groups(
        project_id=os_project.project_object.id, name=resource_name_sec_group1
    )["security_groups"]
    assert len(sgs) == 1
    actual_rules = set(
        Rule.from_dict(dct)
        for dct in sgs[0]["security_group_rules"]
        if dct["ethertype"] == "IPv4"
    )
    assert len(actual_rules) == 5
    assert Rule("ingress", "tcp", 200, 201, "0.0.0.0/0", None) in actual_rules
    assert Rule("ingress", "tcp", 300, 301, "0.0.0.0/0", None) in actual_rules
    assert Rule("ingress", "tcp", 400, 401, "0.0.0.0/0", None) in actual_rules
    assert Rule("ingress", "tcp", 500, 501, "0.0.0.0/0", None) in actual_rules
    remote_group_id1 = [r.remote_group_id for r in actual_rules if r.remote_group_id][0]
    assert Rule("ingress", "tcp", 222, 222, None, remote_group_id1) in actual_rules

    project.compile(
        f"""
import unittest
import openstack

tenant = "{os_project._tenant}"
p = openstack::Provider(
            name="test",
            connection_url="{os_project._auth_url}",
            username="{os_project._username}",
            password="{os_project._password}",
            tenant=tenant)
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)

sg_base = openstack::SecurityGroup(provider=p, project=project, name="{resource_name_sec_group1}", description="test")
# Update direction
openstack::IPrule(
            group=sg_base,
            direction="egress",
            ip_protocol="tcp",
            port_min=200,
            port_max=201,
            remote_prefix="0.0.0.0/0"
)
# Update protocol
openstack::IPrule(
            group=sg_base,
            direction="ingress",
            ip_protocol="udp",
            port_min=300,
            port_max=301,
            remote_prefix="0.0.0.0/0"
)
# Update port
openstack::IPrule(
            group=sg_base,
            direction="ingress",
            ip_protocol="tcp",
            port_min=900,
            port_max=901,
            remote_prefix="0.0.0.0/0"
)
# Update remote prefix
openstack::IPrule(
            group=sg_base,
            direction="ingress",
            ip_protocol="tcp",
            port_min=500,
            port_max=501,
            remote_prefix="192.168.0.0/24"
)
# Attach new remote_group
openstack::GroupRule(
            group=sg_base,
            direction="ingress",
            ip_protocol="tcp",
            port=222,
            remote_group=sg_base3
)

sg_base3 = openstack::SecurityGroup(provider=p, project=project, name="{resource_name_sec_group3}", description="test")
openstack::IPrule(
            group=sg_base3,
            direction="ingress",
            ip_protocol="tcp",
            port=80,
            remote_prefix="0.0.0.0/0"
)
        """
    )

    project.deploy_resource("openstack::SecurityGroup", name=resource_name_sec_group3)
    project.deploy_resource("openstack::SecurityGroup", name=resource_name_sec_group1)
    sgs = neutron.list_security_groups(
        project_id=os_project.project_object.id, name=resource_name_sec_group1
    )["security_groups"]
    assert len(sgs) == 1
    actual_rules = set(
        Rule.from_dict(dct)
        for dct in sgs[0]["security_group_rules"]
        if dct["ethertype"] == "IPv4"
    )
    assert len(actual_rules) == 5
    assert Rule("egress", "tcp", 200, 201, "0.0.0.0/0", None) in actual_rules
    assert Rule("ingress", "udp", 300, 301, "0.0.0.0/0", None) in actual_rules
    assert Rule("ingress", "tcp", 900, 901, "0.0.0.0/0", None) in actual_rules
    assert Rule("ingress", "tcp", 500, 501, "192.168.0.0/24", None) in actual_rules
    remote_group_id2 = [r.remote_group_id for r in actual_rules if r.remote_group_id][0]
    assert remote_group_id1 != remote_group_id2
    assert Rule("ingress", "tcp", 222, 222, None, remote_group_id2) in actual_rules


def test_security_group(project, neutron):
    name = "inmanta_unit_test"
    sgs = neutron.list_security_groups(name=name)
    if len(sgs["security_groups"]) > 0:
        neutron.delete_security_group(sgs["security_groups"][0]["id"])

    project.compile(
        """
import unittest
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)

sg_base = openstack::SecurityGroup(provider=p, project=project, name="%(name)s", description="Clearwater base")
openstack::IPrule(group=sg_base, direction="egress", ip_protocol="all", remote_prefix="0.0.0.0/0")
openstack::IPrule(group=sg_base, direction="ingress", ip_protocol="udp", port_min=161, port_max=162,
                  remote_prefix="0.0.0.0/0")
openstack::IPrule(group=sg_base, direction="ingress", ip_protocol="tcp", port_min=161, port_max=162,
                  remote_prefix="0.0.0.0/0")
        """
        % {"name": name}
    )

    project.deploy_resource("openstack::SecurityGroup")
    sgs = neutron.list_security_groups(name=name)
    assert len(sgs["security_groups"]) == 1
    assert (
        len(
            [
                x
                for x in sgs["security_groups"][0]["security_group_rules"]
                if x["ethertype"] == "IPv4"
            ]
        )
        == 3
    )

    project.compile(
        """
import unittest
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)

sg_base = openstack::SecurityGroup(provider=p, project=project, name="%(name)s", description="Clearwater base")
openstack::IPrule(group=sg_base, direction="egress", ip_protocol="all", remote_prefix="0.0.0.0/0")
openstack::IPrule(group=sg_base, direction="ingress", ip_protocol="udp", port_min=161, port_max=162,
                  remote_prefix="0.0.0.0/0")
openstack::IPrule(group=sg_base, direction="ingress", ip_protocol="tcp", port_min=161, port_max=162,
                  remote_prefix="0.0.0.0/0")
        """
        % {"name": name}
    )

    # deploy a second time
    project.deploy_resource("openstack::SecurityGroup")
    sgs = neutron.list_security_groups(name=name)
    assert len(sgs["security_groups"]) == 1
    assert (
        len(
            [
                x
                for x in sgs["security_groups"][0]["security_group_rules"]
                if x["ethertype"] == "IPv4"
            ]
        )
        == 3
    )

    # purge it
    project.compile(
        """
import unittest
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)

sg_base = openstack::SecurityGroup(provider=p, project=project, name="%(name)s", description="Clearwater base", purged=true)
openstack::IPrule(group=sg_base, direction="egress", ip_protocol="all", remote_prefix="0.0.0.0/0")
openstack::IPrule(group=sg_base, direction="ingress", ip_protocol="udp", port_min=161, port_max=162,
                  remote_prefix="0.0.0.0/0")
        """
        % {"name": name}
    )

    project.deploy_resource("openstack::SecurityGroup")
    sgs = neutron.list_security_groups(name=name)
    assert len(sgs["security_groups"]) == 0


@pytest.mark.skip(reason="This tsest is currently broken and needs to be fixed")
def test_security_group_vm(project, neutron, nova):
    name = "inmanta-unit-test"
    key = (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCsiYV4Cr2lD56bkVabAs2i0WyGSjJbuNHP6IDf8Ru3Pg7DJkz0JaBmETHNjIs+yQ98DNkwH9gZX0"
        "gfrSgX0YfA/PwTatdPf44dwuwWy+cjS2FAqGKdLzNVwLfO5gf74nit4NwATyzakoojHn7YVGnd9ScWfwFNd5jQ6kcLZDq/1w== "
        "bart@wolf.inmanta.com"
    )

    project.compile(
        """
import unittest
import openstack
import ssh

tenant = std::get_env("OS_PROJECT_NAME")
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)

sg_mgmt = openstack::SecurityGroup(provider=p, project=project, name="%(name)s", description="Test Mgmt SG")
openstack::IPrule(group=sg_mgmt, direction="egress", ip_protocol="all", remote_prefix="0.0.0.0/0")
openstack::IPrule(group=sg_mgmt, direction="ingress", ip_protocol="icmp", remote_prefix="0.0.0.0/0")
openstack::IPrule(group=sg_mgmt, direction="ingress", ip_protocol="tcp", port=22, remote_prefix="0.0.0.0/0")
openstack::IPrule(group=sg_mgmt, direction="ingress", ip_protocol="all", remote_prefix="0.0.0.0/0")


os = std::OS(name="cirros", version=0.4, family=std::linux)

key = ssh::Key(name="%(name)s", public_key="%(key)s")
net = openstack::Network(provider=p, project=project, name="%(name)s")
subnet = openstack::Subnet(provider=p, project=project, network=net, dhcp=true, name="%(name)s",
                           network_address="10.255.255.0/24")
vm = openstack::Host(provider=p, project=project, key_pair=key, name="%(name)s", os=os,
                     image=openstack::find_image(p, os), flavor=openstack::find_flavor(p, 1, 0.5), user_data="", subnet=subnet)
vm.vm.security_groups=[sg_mgmt]

vm2 = openstack::Host(provider=p, project=project, key_pair=key, name="%(name)s-2", os=os,
                     image=openstack::find_image(p, os), flavor=openstack::find_flavor(p, 1, 0.5), user_data="", subnet=subnet)
vm2.vm.security_groups=[sg_mgmt]
        """
        % {"name": name, "key": key}
    )

    sg1 = project.get_resource("openstack::SecurityGroup", name=name)
    ctx = project.deploy(sg1)
    assert ctx.status == inmanta.const.ResourceState.deployed
    assert neutron.list_security_groups(name=name)

    n1 = project.get_resource("openstack::Network", name=name)
    ctx = project.deploy(n1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    s1 = project.get_resource("openstack::Subnet", name=name)
    ctx = project.deploy(s1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    h1 = project.get_resource("openstack::VirtualMachine", name=name)
    ctx = project.deploy(h1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    hp1 = project.get_resource("openstack::HostPort", name=name + "_eth0")
    ctx = project.deploy(hp1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    h1 = project.get_resource("openstack::VirtualMachine", name=name + "-2")
    ctx = project.deploy(h1)
    assert ctx.status == inmanta.const.ResourceState.deployed

    hp1 = project.get_resource("openstack::HostPort", name=name + "-2_eth0")
    ctx = project.deploy(hp1)
    assert ctx.status == inmanta.const.ResourceState.deployed


def test_scoping_on_security_group_resource(project, openstack, neutron):
    """
    Verify that the SecurityGroup resource respects the scope of the project.
    """
    project1 = openstack.get_project("inmanta_unit_test1")
    project2 = openstack.get_project("inmanta_unit_test2")

    description_sec_group1 = "test"
    description_sec_group2 = "other description"

    resource_name = project1.get_resource_name("sec_group")

    # Make sure resource exists in project1
    project1.neutron.create_security_group(
        {
            "security_group": {
                "name": resource_name,
                "description": description_sec_group1,
            }
        }
    )

    # Deploy resource with same name in other project
    project.compile(
        f"""
import unittest
import openstack

tenant = "{project2._tenant}"
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
project = openstack::Project(provider=p, name=tenant, description="test", enabled=true, managed=false)

rule1 = openstack::IPrule(ip_protocol="all", port=0, direction="egress", remote_prefix="0.0.0.0/0")
rule2 = openstack::IPrule(ip_protocol="tcp", port=8888, direction="ingress", remote_prefix="0.0.0.0/0")
rule3 = openstack::IPrule(ip_protocol="tcp", port=22, direction="ingress", remote_prefix="0.0.0.0/0")
rule4 = openstack::IPrule(ip_protocol="tcp", port=5432, direction="ingress", remote_prefix="0.0.0.0/0")
security_group = openstack::SecurityGroup(
                            name="{resource_name}",
                            description="{description_sec_group2}",
                            provider=p,
                            project=project,
                            rules=[rule1, rule2, rule3, rule4]
)
        """
    )

    project.deploy_resource("openstack::SecurityGroup")

    sgs = project1.neutron.list_security_groups(
        name=resource_name, project_id=project1.project_object.id
    )
    assert len(sgs["security_groups"]) == 1
    assert sgs["security_groups"][0]["project_id"] == project1.project_object.id
    assert sgs["security_groups"][0]["description"] == description_sec_group1
    ipv4_rules = [
        r
        for r in sgs["security_groups"][0]["security_group_rules"]
        if r["ethertype"] == "IPv4"
    ]
    assert len(ipv4_rules) == 1  # Egress is allowed by default

    sgs = project2.neutron.list_security_groups(
        name=resource_name, project_id=project2.project_object.id
    )
    assert len(sgs["security_groups"]) == 1
    assert sgs["security_groups"][0]["project_id"] == project2.project_object.id
    assert sgs["security_groups"][0]["description"] == description_sec_group2
    ipv4_rules = [
        r
        for r in sgs["security_groups"][0]["security_group_rules"]
        if r["ethertype"] == "IPv4"
    ]
    assert len(ipv4_rules) == 4


def test_shared_network(project, openstack):
    """
    Create a shared network as one tenant and add ports to it as another tenant
    """
    tenant1 = openstack.get_project("tenant1")
    tenant2 = openstack.get_project("tenant2")
    net_name = tenant1.get_resource_name("net")
    key_name = tenant2.get_resource_name("key")
    server_name = tenant2.get_resource_name("server").replace("_", "-")

    # create a shared network in tenant1
    project.compile(
        """
    import unittest
    import openstack

    tenant = "%(project)s"
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="%(name)s", project=project, shared=true)
    subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="%(name)s",
                               network_address="10.255.255.0/24", dns_servers=["8.8.8.8", "8.8.4.4"])
            """
        % {"name": net_name, "project": tenant1._tenant}
    )

    project.deploy_resource("openstack::Network", name=net_name)
    project.deploy_resource("openstack::Subnet", name=net_name)

    # create a hostport on the shared network in tenant2
    project.compile(
        """
    import unittest
    import openstack
    import ssh

    tenant = "%(project)s"
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n1 = openstack::Network(provider=p, name="%(net_name)s", project=project, managed=false)
    s1 = openstack::Subnet(provider=p, project=project, network=n1, dhcp=true, name="%(net_name)s",
                               network_address="10.255.255.0/24", dns_servers=["8.8.8.8", "8.8.4.4"], managed=false)

    n2 = openstack::Network(provider=p, name="%(net_name)s2", project=project, managed=true)
    s2 = openstack::Subnet(provider=p, project=project, network=n2, dhcp=true, name="%(net_name)s2",
                           network_address="10.255.254.0/24", dns_servers=["8.8.8.8", "8.8.4.4"], managed=true)

    os = std::OS(name="cirros", version=0.4, family=std::linux)
    key = ssh::Key(name="%(key_name)s", public_key="")
    vm = openstack::Host(provider=p, project=project, key_pair=key, name="%(server_name)s", os=os,
                         image=openstack::find_image(p, os), flavor=openstack::find_flavor(p, 1, 0.5), user_data="",
                         subnet=s2)
    port = openstack::HostPort(provider=p, vm=vm.vm, subnet=s1, name="%(server_name)s_eth1", address="10.255.255.123",
                               project=project, port_index=2, purged=false, dhcp=false)
            """
        % {
            "net_name": net_name,
            "project": tenant2._tenant,
            "key_name": key_name,
            "server_name": server_name,
        }
    )

    project.deploy_resource("openstack::Network", name=net_name + "2")
    project.deploy_resource("openstack::Subnet", name=net_name + "2")
    project.deploy_resource("openstack::VirtualMachine")
    project.deploy_resource("openstack::HostPort")

    project.compile(
        """
    import unittest
    import openstack
    import ssh

    tenant = "%(project)s"
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n1 = openstack::Network(provider=p, name="%(net_name)s", project=project, managed=false)
    s1 = openstack::Subnet(provider=p, project=project, network=n1, dhcp=true, name="%(net_name)s",
                               network_address="10.255.255.0/24", dns_servers=["8.8.8.8", "8.8.4.4"], managed=false)

    n2 = openstack::Network(provider=p, name="%(net_name)s2", project=project, managed=true)
    s2 = openstack::Subnet(provider=p, project=project, network=n2, dhcp=true, name="%(net_name)s2",
                           network_address="10.255.254.0/24", dns_servers=["8.8.8.8", "8.8.4.4"], managed=true)

    n3 = openstack::Network(provider=p, name="%(net_name)s3", project=project, managed=true)
    s3 = openstack::Subnet(provider=p, project=project, network=n3, dhcp=true, name="%(net_name)s3",
                           network_address="10.255.253.0/24", dns_servers=["8.8.8.8", "8.8.4.4"], managed=true)

    os = std::OS(name="cirros", version=0.4, family=std::linux)
    key = ssh::Key(name="%(key_name)s", public_key="")
    vm = openstack::Host(provider=p, project=project, key_pair=key, name="%(server_name)s", os=os,
                         image=openstack::find_image(p, os), flavor=openstack::find_flavor(p, 1, 0.5), user_data="",
                         subnet=s2)

    openstack::HostPort(provider=p, vm=vm.vm, subnet=s1, name="%(server_name)s_eth1", address="10.255.255.123",
                        project=project, port_index=2, purged=false, dhcp=false)

    openstack::HostPort(provider=p, vm=vm.vm, subnet=s3, name="%(server_name)s_eth2", address="10.255.253.12",
                        project=project, port_index=3, purged=false, dhcp=false)
            """
        % {
            "net_name": net_name,
            "project": tenant2._tenant,
            "key_name": key_name,
            "server_name": server_name,
        }
    )

    project.deploy_resource("openstack::Network", name=net_name + "3")
    project.deploy_resource("openstack::Subnet", name=net_name + "3")
    project.deploy_resource("openstack::HostPort", name=server_name + "_eth2")


def test_allowed_addr_port(project, openstack):
    """
    Test creating a port with allowed address pairs
    """
    tenant1 = openstack.get_project("tenant1")
    net_name = tenant1.get_resource_name("net")
    port_name = tenant1.get_resource_name("port")
    key_name = tenant1.get_resource_name("key")
    server_name = tenant1.get_resource_name("server").replace("_", "-")

    project.compile(
        """
    import unittest
    import openstack
    import ssh

    tenant = "%(project)s"
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="%(name)s", project=project)
    subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="%(name)s",
                               network_address="10.255.255.0/24", dns_servers=["8.8.8.8", "8.8.4.4"])

    os = std::OS(name="cirros", version=0.4, family=std::linux)
    key = ssh::Key(name="%(key_name)s", public_key="")

    vm = openstack::VirtualMachine(provider=p, project=project, key_pair=key, name="%(server_name)s",
                                   image=openstack::find_image(p, os), flavor=openstack::find_flavor(p, 1, 0.5), user_data="")

    p1 = openstack::AddressPair(address="10.255.255.0/24")
    p2 = openstack::AddressPair(address="10.255.0.0/24", mac="12:23:34:45:56:67")
    port = openstack::HostPort(provider=p, project=project, name="%(port_name)s", subnet=subnet, address="10.255.255.10",
                               dhcp=false, allowed_address_pairs=[p1, p2], vm=vm)
    vm.eth0_port = port
            """
        % {
            "name": net_name,
            "project": tenant1._tenant,
            "port_name": port_name,
            "server_name": server_name,
            "key_name": key_name,
        }
    )

    project.deploy_resource("openstack::Network", name=net_name)
    project.deploy_resource("openstack::Subnet", name=net_name)
    project.deploy_resource("openstack::VirtualMachine", name=server_name)
    project.deploy_resource("openstack::HostPort", name=port_name)

    ports = tenant1.neutron.list_ports(name=port_name)["ports"]
    assert len(ports) == 1
    assert len(ports[0]["allowed_address_pairs"]) == 2

    # recheck the config
    project.deploy_resource("openstack::HostPort", name=port_name)


@pytest.mark.parametrize(
    "disable_gateway_ip,gateway_ip",
    [
        (False, None),
        (False, "10.255.255.27"),
        (True, None),
        (  # Should not be used in practice. disable_gateway_ip takes precedence.
            True,
            "10.255.255.111",
        ),
    ],
)
def test_gateway_ip(project, openstack, disable_gateway_ip, gateway_ip):
    """
    Test whether the gateway_ip and the disable_gateway_ip settings of a subnet work correctly.
    """
    tenant1 = openstack.get_project("tenant1")
    net_name = tenant1.get_resource_name("net")
    subnet_name = tenant1.get_resource_name("subnet")

    gateway_ip_model = f'"{gateway_ip}"' if gateway_ip is not None else "null"
    project.compile(
        f"""
    import unittest
    import openstack

    tenant = "{tenant1._tenant}"
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="{net_name}", project=project)
    subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="{subnet_name}",
                               network_address="10.255.255.0/24", dns_servers=["8.8.8.8", "8.8.4.4"],
                               gateway_ip={gateway_ip_model}, disable_gateway_ip={str(disable_gateway_ip).lower()})
            """
    )

    project.deploy_resource("openstack::Network", name=net_name)

    # Check initial state
    changes = project.dryrun_resource("openstack::Subnet", name=subnet_name)
    assert changes

    # Deploy subnet
    project.deploy_resource("openstack::Subnet", name=subnet_name)

    # Verify state on Openstack
    subnets = tenant1.neutron.list_subnets(name=subnet_name)["subnets"]
    assert len(subnets) == 1
    subnet = subnets[0]
    if disable_gateway_ip:
        assert subnet["gateway_ip"] is None
    elif gateway_ip is None:
        # The first IP of the subnet should be set
        assert subnet["gateway_ip"] == "10.255.255.1"
    else:
        assert subnet["gateway_ip"] == gateway_ip

    # Ensure convergence
    changes = project.dryrun_resource("openstack::Subnet", name=subnet_name)
    assert not changes


def test_issue_7_and_286(project, openstack):
    tenant1 = openstack.get_project("tenant1")
    net_name = tenant1.get_resource_name("net")
    port_name = tenant1.get_resource_name("port")
    key_name = tenant1.get_resource_name("key")
    server_name = tenant1.get_resource_name("server").replace("_", "-")

    def _get_model(purged: bool) -> str:
        return f"""
    import unittest
    import openstack
    import ssh

    tenant = "{tenant1._tenant}"
    p = openstack::Provider(
        name="test",
        connection_url=std::get_env("OS_AUTH_URL"),
        username=std::get_env("OS_USERNAME"),
        password=std::get_env("OS_PASSWORD"),
        tenant=tenant
    )
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="{net_name}", project=project)
    subnet = openstack::Subnet(
        provider=p,
        project=project,
        network=n,
        dhcp=true,
        name="{net_name}",
        network_address="10.255.255.0/24",
        dns_servers=["8.8.8.8", "8.8.4.4"],
        purged={str(purged).lower()},
    )

    os = std::OS(name="cirros", version=0.4, family=std::linux)
    key = ssh::Key(name="{key_name}", public_key="")

    vm = openstack::VirtualMachine(
        provider=p,
        project=project,
        key_pair=key,
        name="{server_name}",
        image=openstack::find_image(p, os),
        flavor=openstack::find_flavor(p, 1, 0.5),
        user_data="",
        purged={str(purged).lower()},
    )

    port = openstack::HostPort(
        provider=p,
        project=project,
        name="{port_name}",
        subnet=subnet,
        address="10.255.255.10",
        dhcp=false,
        vm=vm,
        retries=1,
        wait=0,
        purged={str(purged).lower()},
    )
    vm.eth0_port = port
            """

    project.compile(_get_model(purged=False))
    project.deploy_resource("openstack::Network", name=net_name)
    project.deploy_resource("openstack::Subnet", name=net_name)
    # HostPort doesn't have VM so it will be skipped, but shouldn't fail.
    project.deploy_resource(
        "openstack::HostPort",
        name=port_name,
        status=inmanta.const.ResourceState.skipped,
    )

    project.compile(_get_model(purged=True))
    # HostPort doesn't exist, so it should succeed.
    project.deploy_resource(
        "openstack::HostPort",
        name=port_name,
    )
