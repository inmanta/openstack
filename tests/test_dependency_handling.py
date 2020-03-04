from inmanta.resources import Id

all_model="""
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
    subnet = openstack::Subnet(provider=p, project=project, network=net, dhcp=true, name="mysub", network_address="10.255.255.0/24")
    vm = openstack::Host(
        provider=p,
        project=project,
        key_pair=key,
        name="{{name}}myhost",
        image="abcd",
        flavor="1c1m",
        user_data="",
        subnet=subnet,
        os=std::linux)
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
end
"""

def test_dependency_handling(project):
    project.compile(
        all_model+"""

            AllFor(name="t1")
            AllFor(name="t2")
        """
    )

    # no leakage between providers
    for name, resource in project.resources.items():
        if not "openstack" in name.get_entity_type():
            continue
        agentname = name.get_agent_name()
        for r in resource.requires: 
            #ensure clean typing
            assert isinstance(r, Id)
            if not "openstack" in r.get_entity_type():
                continue
            assert agentname == r.get_agent_name()

    def assert_before(typea, typeb, tenant="t1"):
        for tenant in ["t1","t2"]:
            a = project.get_resource(f"openstack::{typea}", admin_user=tenant)
            b = project.get_resource(f"openstack::{typeb}", admin_user=tenant)
            assert b.id in a.requires


    assert_before("Network", "Project")

    assert_before("Subnet", "Project")
    assert_before("Subnet", "Network")

    assert_before("Router", "Network")
    assert_before("Router", "Subnet")
    assert_before("Router", "Project")

    assert_before("VirtualMachine", "Project")
    assert_before("VirtualMachine", "Subnet")

    assert_before("HostPort", "Project")
    assert_before("HostPort", "VirtualMachine")

    assert_before("FloatingIP", "Router")
    assert_before("FloatingIP", "HostPort")
    assert_before("FloatingIP", "Network")