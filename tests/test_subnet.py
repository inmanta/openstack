from common import reload, facts, dryrun_resource, ib
from inmanta import const

def test_subnet_pre(openstack):
    d1p1 = openstack.get_shared_project()

    def dump_subnets(name, user):
        connection = user.connection
        nets =  [x.name + " " + x.project_id for x in  connection.network.subnets()]
        print(name, user._username, len(nets), nets)
        return len(nets)

    assert 0 == dump_subnets("before creation", d1p1._user)

    n1 = d1p1.create_network("for_subnet")

    s1 = d1p1.create_subnet("subnet", n1.id)

    assert 1 == dump_subnets("after creation", d1p1._user)

    d1p1._user.connection.network.delete_subnet(s1.id)

    assert 0 == dump_subnets("after delete", d1p1._user)

def test_subnet_full(project, openstack):
    osproject = openstack.get_shared_project()
    
    user = osproject._admin.snippet()

    def make(net_name="test_net", name="test_net", purged=False, dns="8.8.4.4"):
        project.compile("""
import unittest
import openstack

p = %(user)s
project = openstack::Project(provider=p, name=p.tenant, description="", enabled=true, managed=false)
n = openstack::Network(provider=p, name="%(net_name)s", project=project)
subnet = openstack::Subnet(provider=p, project=project, network=n, dhcp=true, name="%(name)s",
                            network_address="10.255.255.0/24", dns_servers=["8.8.8.8", "%(dns)s"], purged=%(purged)s)
            """ % {"user":user,"name":name, "purged":ib(purged), "dns":dns, "net_name":net_name})
        return reload(project.get_resource("openstack::Subnet", name="test_net"))

    res = make()

    # check serialization
    assert isinstance(res.network, dict)
    #check deserialization
    res.decode()
    assert "NetworkReference" in str(type(res.network)) 

    # check facts pre deploy
    assert facts(project, res) == {}

    # dryrun
    dr = dryrun_resource(project, res)
    assert "purged" in dr and dr["purged"]["current"] == True

    # deploy no net
    project.deploy_resource("openstack::Subnet", status=const.ResourceState.failed)

    # deploy
    project.deploy_resource("openstack::Network", name="test_net")
    project.deploy_resource("openstack::Subnet")

    subnet = osproject.find_subnet("test_net")
    assert subnet is not None
    assert len(subnet.dns_nameservers) == 2

    # dryrun
    dr = dryrun_resource(project, res)
    assert len(dr) == 0

    # check facts post deploy
    myfacts = facts(project, res)
    expected  = ['updated_at', 'ipv6_ra_mode', 'allocation_pools', 'host_routes', 'revision_number', 'ipv6_address_mode', 'id', 'dns_nameservers', 'use_default_subnet_pool', 'gateway_ip', 'location', 'project_id', 'description', 'tags', 'is_dhcp_enabled', 'subnet_pool_id', 'cidr', 'service_types', 'name', 'segment_id', 'network_id', 'created_at', 'ip_version']

    for key in expected:
        assert key in myfacts

    # update DNS
    res = make(dns="1.1.1.1")

    #dryrun
    dr = dryrun_resource(project, res)
    assert "dns_servers" in dr

    #perform update
    project.deploy_resource("openstack::Subnet")
    subnet = osproject.find_subnet("test_net")
    assert subnet is not None
    assert len(subnet.dns_nameservers) == 2
    assert "1.1.1.1" in subnet.dns_nameservers

    #perform impossible update
    res = make(dns="1.1.1.1", net_name="test_net_2")
    
    dr = dryrun_resource(project, res)
    assert "network" in dr 

    project.deploy_resource("openstack::Network", name="test_net_2")

    dr = dryrun_resource(project, res)
    assert "network" in dr 

    project.deploy_resource("openstack::Subnet", status=const.ResourceState.failed)

    #delete
    res = make(dns="1.1.1.1", purged=True)
    dr = dryrun_resource(project, res)
    assert "purged" in dr and dr["purged"]["current"] == False

    project.deploy_resource("openstack::Subnet")
    subnet = osproject.find_subnet("test_net")
    assert subnet is None