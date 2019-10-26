import os

import inmanta

def test_flavor(project):
    flavor_name = "test-flavor"
    project.compile(f"""
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
provider = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)

flavor=openstack::Flavor(
    provider=provider,
    name="{flavor_name}",
    ram=1024,
    vcpus=4,
    disk=10
)
""")
    created_flavor = project.get_resource("openstack::Flavor", name=flavor_name)
    assert created_flavor
    assert created_flavor.ram == 1024
    assert created_flavor.vcpus == 4
    assert created_flavor.disk == 10

    assert created_flavor.flavorid == "auto"
    assert created_flavor.ephemeral == 0
    assert created_flavor.swap == 0
    assert created_flavor.rxtx_factor == 1.0
    assert created_flavor.is_public
    assert created_flavor.extra_specs == {}
    assert created_flavor.description == ""

    assert created_flavor.admin_user == os.environ.get("OS_USERNAME")
    assert created_flavor.admin_password == os.environ.get("OS_PASSWORD")
    assert created_flavor.admin_tenant == os.environ.get("OS_PROJECT_NAME")
    assert created_flavor.auth_url == os.environ.get("OS_AUTH_URL")

    ctx_dryrun1 = project.dryrun(created_flavor)
    assert ctx_dryrun1.changes

    ctx = project.deploy(created_flavor)
    assert ctx.status == inmanta.const.ResourceState.deployed

    ctx_dryrun2 = project.dryrun(created_flavor)
    assert not ctx_dryrun2.changes
