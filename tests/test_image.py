import time

import inmanta
import pytest

TEST_IMAGE_NAME = "inmanta_unit_test"
TEST_PROJECT_NAME = "inmanta_unit_test"
OPENSTACK_BASE = f"""
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
provider = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)

"""
CIRROS_URI = "https://www.example.com/" # not an image but speeds up tests by a lot

def get_test_image(glance):
    return [image for image in glance.images.list() if image.name == TEST_IMAGE_NAME]

def cleanup_image(glance):
    for image in get_test_image(glance):
        glance.images.delete(image.id)

@pytest.fixture()
def cleanup(glance):
    cleanup_image(glance)
    yield
    cleanup_image(glance)

def test_create_image(project, glance, cleanup):
    project.compile(OPENSTACK_BASE + f"""
image=openstack::Image(
    provider=provider,
    name="{TEST_IMAGE_NAME}",
    uri="{CIRROS_URI}",
    metadata = {{
        "test": "test"
    }}
)
""")
    created_image = project.get_resource("openstack::Image", name=TEST_IMAGE_NAME)
    assert created_image
    assert created_image.name
    assert created_image.uri

    assert created_image.container_format == "bare"
    assert created_image.disk_format == "qcow2"
    assert not created_image.image_id
    assert created_image.visibility == "public"
    assert not created_image.protected
    assert created_image.skip_on_deploy
    assert not created_image.purge_on_delete
    assert created_image.metadata == {"test": "test"}

    ctx_dryrun_1 = project.dryrun(created_image)
    assert ctx_dryrun_1.changes

    ctx_deploy_1 = project.deploy(created_image)
    assert ctx_deploy_1.status == inmanta.const.ResourceState.skipped

    while True:
        test_image = get_test_image(glance)[0]
        if test_image.status == "active":
            break
        time.sleep(0.1)

    ctx_deploy_2 = project.deploy(created_image)
    assert ctx_deploy_2.status == inmanta.const.ResourceState.deployed

def test_create_image_no_skip(project, glance, cleanup):
    project.compile(OPENSTACK_BASE + f"""
image=openstack::Image(
    provider=provider,
    name="{TEST_IMAGE_NAME}",
    uri="{CIRROS_URI}",
    skip_on_deploy=false
)
""")
    created_image = project.get_resource("openstack::Image", name=TEST_IMAGE_NAME)
    assert not created_image.skip_on_deploy

    ctx_dryrun_1 = project.dryrun(created_image)
    assert ctx_dryrun_1.changes

    ctx_deploy_1 = project.deploy(created_image)
    assert ctx_deploy_1.status == inmanta.const.ResourceState.deployed
