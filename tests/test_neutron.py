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
import inmanta


def test_net(project, neutron):
    try:
        project.compile("""
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="test_net", project=project, external=true)
            """)

        n1 = project.deploy_resource("openstack::Network", name="test_net")

        networks = neutron.list_networks(name=n1.name)["networks"]
        assert len(networks) == 1

        assert networks[0]["router:external"]

        ctx = project.deploy(n1)
        assert ctx.status == inmanta.const.ResourceState.deployed

        project.compile("""
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="test_net", project=project, purged=true)
            """)

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
        project.compile("""
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="%(name)s", project=project)
    subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="%(name)s",
                               network_address="10.255.255.0/24", dns_servers=["8.8.8.8", "8.8.4.4"])
            """ % {"name": name})

        net = project.deploy_resource("openstack::Network")
        subnet = project.deploy_resource("openstack::Subnet")

        subnets = neutron.list_subnets(name=subnet.name)["subnets"]
        assert len(subnets) == 1
        assert len(neutron.list_networks(name=net.name)["networks"]) == 1

        os_subnet = subnets[0]
        assert len(os_subnet["dns_nameservers"]) == 2

        project.compile("""
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="%(name)s", project=project, purged=true)
    subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="%(name)s",
                               network_address="10.255.255.0/24", purged=true)
            """ % {"name": name})

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

    project.compile("""
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
        """ % {"external": external["name"], "name": name})

    net = project.deploy_resource("openstack::Network")
    subnet = project.deploy_resource("openstack::Subnet")
    project.deploy_resource("openstack::Router")

    routers = neutron.list_routers(name=name)["routers"]
    assert len(routers) == 1
    assert len(neutron.list_networks(name=net.name)["networks"]) == 1
    assert len(neutron.list_subnets(name=subnet.name)["subnets"]) == 1

    ports = neutron.list_ports(device_id=routers[0]["id"])["ports"]
    assert len(ports) == 2

    project.compile("""
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
        """ % {"external": external["name"], "name": name})

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

    project.compile("""
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
        """ % {"external": external["name"], "name": name})

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
    project.compile("""
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
        """ % {"external": external["name"], "name": name})

    project.deploy_resource("openstack::RouterPort")
    project.deploy_resource("openstack::Router")
    subnet = project.deploy_resource("openstack::Subnet")
    net = project.deploy_resource("openstack::Network")

    routers = neutron.list_routers(name=name)["routers"]
    assert len(routers) == 0
    assert len(neutron.list_networks(name=net.name)["networks"]) == 0
    assert len(neutron.list_subnets(name=subnet.name)["subnets"]) == 0


def test_security_group(project, neutron):
    name = "inmanta_unit_test"
    sgs = neutron.list_security_groups(name=name)
    if len(sgs["security_groups"]) > 0:
        neutron.delete_security_group(sgs["security_groups"][0]["id"])

    project.compile("""
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
        """ % {"name": name})

    project.deploy_resource("openstack::SecurityGroup")
    sgs = neutron.list_security_groups(name=name)
    assert len(sgs["security_groups"]) == 1
    assert len([x for x in sgs["security_groups"][0]["security_group_rules"] if x["ethertype"] == "IPv4"]) == 3

    project.compile("""
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
        """ % {"name": name})

    # deploy a second time
    project.deploy_resource("openstack::SecurityGroup")
    sgs = neutron.list_security_groups(name=name)
    assert len(sgs["security_groups"]) == 1
    assert len([x for x in sgs["security_groups"][0]["security_group_rules"] if x["ethertype"] == "IPv4"]) == 3

    project.compile("""
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
        """ % {"name": name})

    project.deploy_resource("openstack::SecurityGroup")
    sgs = neutron.list_security_groups(name=name)
    assert len(sgs["security_groups"]) == 0
