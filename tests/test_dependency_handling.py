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
