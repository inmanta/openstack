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
    n = openstack::Network(provider=p, name="test_net", project=project)
            """)

        n1 = project.deploy_resource("openstack::Network", name="test_net")

        networks = neutron.list_networks(name=n1.name)["networks"]
        assert len(networks) == 1

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
                               network_address="10.255.255.0/24")
            """ % {"name": name})

        net = project.deploy_resource("openstack::Network")
        subnet = project.deploy_resource("openstack::Subnet")

        assert len(neutron.list_subnets(name=subnet.name)["subnets"]) == 1
        assert len(neutron.list_networks(name=net.name)["networks"]) == 1

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
