def test_openstack_fixture(openstack):
    openstack.get_shared_project()
    openstack.get_shared_project_d2()