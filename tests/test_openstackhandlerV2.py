import pytest
from common import reload
from conftest import Project, User


def test_get_project_id(project, openstack):
    d1: Project = openstack.get_shared_project()
    d2: Project = openstack.get_shared_project_d2()

    p1 = d1.project_object.id
    p2 = d2.project_object.id

    pn = d1.project_object.name

    user = d1._admin

    # acquire a handler
    project.compile("""
import unittest
import openstack

p = %(user)s
project = openstack::Project(provider=p, name=p.tenant, description="", enabled=true, managed=false)

openstack::Network(provider=p, name="test_net", project=project, external=true)
        """ % {"user": user.snippet()})

    res = reload(project.get_resource("openstack::Network", name="test_net"))

    h1 = project.get_handler(res, False)

    from inmanta_plugins.openstack import UserReference, ProjectReference, OpenStackException

    def assert_project(user: User, project: User, project_id):
        ur = UserReference(user._username, user._password,
                           user._tenant, user._auth_url, user._domain, user._domain)
        pr = ProjectReference(project._domain, project._tenant)

        pid = h1.get_project_id(ur,pr)
        assert pid == project_id

    print("P1: ", p1)
    print("P2: ", p2)

    assert_project(d1._super_admin, d1._user, p1)
    assert_project(d1._admin, d1._user, p1)
    assert_project(d2._admin, d1._user, p1)
    assert_project(d1._user, d1._user, p1)

    assert_project(d1._super_admin, d2._user, p2)
    assert_project(d1._admin, d2._user, p2)
    assert_project(d2._admin, d2._user, p2)
    assert_project(d2._user, d2._user, p2)

    with pytest.raises(OpenStackException):
        assert_project(d1._user, d2._user, None)
    with pytest.raises(OpenStackException):
        assert_project(d2._user, d1._user, None)
    
