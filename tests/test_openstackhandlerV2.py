import pytest

from common import reload
from inmanta.agent import cache
from inmanta.agent import handler
from inmanta.agent import io as agent_io
from pytest_inmanta.plugin import MockAgent


@pytest.fixture
def handlerv2(project):
    from inmanta_plugins.openstack import OpenStackHandlerV2
    
    c = cache.AgentCache()
    c.open_version(1)
    
    agent = MockAgent("local:")
    
    
    p = OpenStackHandlerV2(agent=agent, io="")
    p.set_cache(c)
    p.get_file = None
    p.stat_file = None
    p.upload_file = None
    p.run_sync = None
    
    yield p
    
    c.close_version(1)



def test_get_project_id(handlerv2, openstack):
    d1 = openstack.get_shared_project()
    d2 = openstack.get_shared_project_d2()

    p1 = d1.project_object.id
    p2 = d2.project_object.id

    pn = d1.project_object.name

    user = d1._admin

    from inmanta_plugins.openstack import UserReference, ProjectReference, OpenStackHandlerV2, OpenStackException

    h1 = handlerv2

    def assert_project(user, project, project_id):
        ur = UserReference(user._username, user._password,
                           user._tenant, user._auth_url, user._domain, user._domain)
        pr = ProjectReference(project._domain, project._tenant)

        #test cache as well
        assert id(h1.get_keystone(ur)) == id(h1.get_keystone(ur))

        pid = h1.get_project_id(ur,pr)
        assert pid == project_id

        dname,pname = h1._get_project_domain(ur, pid)
        assert dname == project._domain
        assert pname == project._tenant

    print("P1: ", p1)
    print("P2: ", p2)

    assert_project(d1._admin, d1._user, p1)
    assert_project(d2._admin, d1._user, p1)
    assert_project(d1._user, d1._user, p1)

    assert_project(d1._admin, d2._user, p2)
    assert_project(d2._admin, d2._user, p2)
    assert_project(d2._user, d2._user, p2)

    with pytest.raises(OpenStackException):
        assert_project(d1._user, d2._user, None)
    with pytest.raises(OpenStackException):
        assert_project(d2._user, d1._user, None)

    
