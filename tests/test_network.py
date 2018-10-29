import pytest
from common import reload, facts, dryrun_resource, ib

def test_net(project, openstack):
    osproject = openstack.get_shared_project()

    user = osproject._admin.snippet()

    def make(external=True, purged=False):
        model = """
    import unittest
    import openstack

    p = %(user)s
    project = openstack::Project(provider=p, name=p.tenant, description="", enabled=true, managed=false)
    n = openstack::Network(provider=p, name="test_net", project=project, external=%(external)s, purged=%(purged)s)
            """%{"user":user,
                 "purged":ib(purged),
                 "external": ib(external)}
        project.compile(model)
        return reload(project.get_resource("openstack::Network", name="test_net"))
    
    # create
    res = make()

    # check serialization
    assert isinstance(res.user, dict)
    #check deserialization
    res.decode()
    assert "UserReference" in str(type(res.user)) 
    assert res.name == "test_net"
    assert repr(res.user) == "UserReference(connection_url='%(url)s',password='%(pass)s',project_domain_name='%(domain)s',project_name='%(project)s',user_domain_name='%(domain)s',username='%(username)s')"%{
                            "domain":osproject._admin._domain,
                            "project":osproject._admin._tenant,
                            "username":osproject._admin._username,
                            "url":osproject._admin._auth_url,
                            "pass":osproject._admin._password
                        }

    # check facts pre deploy
    assert facts(project, res) == {}

    # dryrun
    dr = dryrun_resource(project, res)
    assert "purged" in dr and dr["purged"]["current"] == True

    # deploy
    project.deploy_resource("openstack::Network", name="test_net")
    net = osproject.assert_network("test_net")
    assert net is not None
    assert net.is_router_external

    # dryrun
    dr = dryrun_resource(project, res)
    assert len(dr) == 0

    # check facts post deploy
    myfacts = facts(project, res)
    expected = ['updated_at', 'dns_domain', 'provider_physical_network', 'is_vlan_transparent', 'revision_number', 'ipv4_address_scope_id', 'id', 'availability_zone_hints', 'availability_zones', 'segments', 'location', 'project_id', 'ipv6_address_scope_id', 'status', 'description', 'provider_network_type', 'tags', 'is_router_external', 'is_default', 'is_port_security_enabled', 'subnet_ids', 'qos_policy_id', 'name', 'created_at', 'mtu', 'provider_segmentation_id', 'is_admin_state_up', 'is_shared']
    for key in expected:
        assert key in myfacts

    # update
    res = make(external=False)

    #dryrun
    dr = dryrun_resource(project, res)
    assert "external" in dr and dr["external"]["current"] == True

    # perform update
    project.deploy_resource("openstack::Network", name="test_net")
    net = osproject.assert_network("test_net")
    assert net is not None
    assert not net.is_router_external

    #dryrun
    dr = dryrun_resource(project, res)
    assert len(dr) == 0

    #delete
    res = make(external=False, purged=True)

    #dryrun
    dr = dryrun_resource(project, res)
    assert "purged" in dr and dr["purged"]["current"] == False

    #perform delete
    project.deploy_resource("openstack::Network", name="test_net")
    net = osproject.assert_network("test_net")
    assert net is None
    
    #dryrun
    dr = dryrun_resource(project, res)
    assert len(dr) == 0
