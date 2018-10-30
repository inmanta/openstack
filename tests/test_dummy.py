

def test_dummy(project, keystone, nova, neutron):
    project_name = "inmanta_unit_test"
    project.compile("""
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name="%s", description="", enabled=true)
            """ % project_name)