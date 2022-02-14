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
from inmanta.resources import Id

all_model = """
import openstack
import ssh
entity AllFor:
    string name
end
implement AllFor using allfor
implementation allfor for AllFor:
    p = openstack::Provider(
        name=name,
        connection_url="http://example/",
        username=name,
        password="voom",
        tenant=name,
    )
    key = ssh::Key(name="mykey", public_key="AAAAAAAAAAAAa")
    project = openstack::Project(provider=p, name=name, description="", enabled=true)
    net = openstack::Network(provider=p, project=project, name="mynet")
    subnet = openstack::Subnet(
        provider=p,
        project=project,
        network=net,
        dhcp=true,
        name="mysub",
        network_address="10.255.255.0/24"
    )
    vm = openstack::Host(
        provider=p,
        project=project,
        key_pair=key,
        name="{{name}}myhost",
        image="abcd",
        flavor="1c1m",
        user_data="",
        subnet=subnet,
        os=std::linux,
        security_groups=sg
        )
    router = openstack::Router(name="myr",
                      provider=p,
                      project=project,
                      subnets=[subnet],
                      ext_gateway=net
                      )
    fip = openstack::FloatingIP(
        provider=p,
        project=project,
        external_network=net,
        port=vm.vm.eth0_port,
    )

    sg = openstack::SecurityGroup(
        provider=p,
        project=project,
        name="sg1"
    )
end
"""


def test_dependency_handling(project):
    project.compile(
        all_model
        + """

            AllFor(name="t1")
            AllFor(name="t2")
        """
    )

    # no leakage between providers
    for name, resource in project.resources.items():
        if "openstack" not in name.get_entity_type():
            continue
        agentname = name.get_agent_name()
        for r in resource.requires:
            # ensure clean typing
            assert isinstance(r, Id)
            if "openstack" not in r.get_entity_type():
                continue
            assert agentname == r.get_agent_name()

    def assert_requires(typea, typeb, tenant="t1"):
        for tenant in ["t1", "t2"]:
            a = project.get_resource(f"openstack::{typea}", admin_user=tenant)
            b = project.get_resource(f"openstack::{typeb}", admin_user=tenant)
            assert b.id in a.requires

    assert_requires("Network", "Project")

    assert_requires("Subnet", "Project")
    assert_requires("Subnet", "Network")

    assert_requires("Router", "Network")
    assert_requires("Router", "Subnet")
    assert_requires("Router", "Project")

    assert_requires("VirtualMachine", "Project")
    assert_requires("VirtualMachine", "Subnet")

    assert_requires("HostPort", "Project")
    assert_requires("HostPort", "VirtualMachine")

    assert_requires("FloatingIP", "Router")
    assert_requires("FloatingIP", "HostPort")
    assert_requires("FloatingIP", "Network")

    assert_requires("VirtualMachine", "SecurityGroup")
    assert_requires("SecurityGroup", "Project")


def test_issue_79(project):
    """
    When a VM and its hostport are being purged, the hostport should be deleted before the VM gets deleted.
    """

    def _get_model(purged: bool):
        return f"""
    import unittest
    import openstack
    import ssh

    tenant = "tenant"
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name=tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="net", project=project)
    subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="subnet",
                               network_address="10.255.255.0/24", dns_servers=["8.8.8.8", "8.8.4.4"])

    os = std::OS(name="cirros", version=0.4, family=std::linux)
    key = ssh::Key(name="key", public_key="")

    vm = openstack::VirtualMachine(provider=p, project=project, key_pair=key, name="server",
                                image=openstack::find_image(p, os), flavor=openstack::find_flavor(p, 1, 0.5), user_data="",
                                purged={str(purged).lower()})

    port = openstack::HostPort(provider=p, project=project, name="port", subnet=subnet, address="10.255.255.10",
                               dhcp=false, vm=vm, purged={str(purged).lower()})
    vm.eth0_port = port
        """

    project.compile(_get_model(purged=False))
    vm = project.get_resource("openstack::VirtualMachine")
    hostport = project.get_resource("openstack::HostPort")
    assert vm.id in hostport.requires
    assert hostport.id not in vm.requires

    project.compile(_get_model(purged=True))
    vm = project.get_resource("openstack::VirtualMachine")
    hostport = project.get_resource("openstack::HostPort")
    assert vm.id not in hostport.requires
    assert hostport.id in vm.requires
