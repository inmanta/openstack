"""
    Copyright 2022 Inmanta

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    Contact: code@inmanta.com
"""
import inmanta
import pytest

TEST_IMAGE_NAME = "inmanta_unit_test"
TEST_PROJECT_NAME = "inmanta_unit_test"
CIRROS_URI = "https://www.example.com/"  # not an image but speeds up tests by a lot

OPENSTACK_BASE = """
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
provider = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)

"""


def get_test_image(glance):
    return [image for image in glance.images.list() if image.name == TEST_IMAGE_NAME]


def cleanup_image(glance):
    for image in get_test_image(glance):
        if image.protected:
            glance.images.update(image.id, protected=False)
        glance.images.delete(image.id)


@pytest.fixture()
def cleanup(glance):
    cleanup_image(glance)
    yield
    cleanup_image(glance)


def test_create_image(project, glance, cleanup):
    project.compile(
        OPENSTACK_BASE
        + f"""
image=openstack::Image(
    provider=provider,
    name="{TEST_IMAGE_NAME}",
    uri="{CIRROS_URI}",
    metadata = {{
        "test": "test"
    }}
)

"""
    )
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

    handler = project.get_handler(created_image, run_as_root=False)
    handler.pre(ctx=None, resource=created_image)
    image_id = get_test_image(glance)[0].id
    handler._wait_for_image_to_become_active(image_id)

    ctx_deploy_2 = project.deploy(created_image)
    assert ctx_deploy_2.status == inmanta.const.ResourceState.deployed

    matching_images = [
        image for image in glance.images.list() if TEST_IMAGE_NAME == image.name
    ]
    assert len(matching_images) == 1


def test_create_image_no_skip(project, glance, cleanup):
    project.compile(
        OPENSTACK_BASE
        + f"""
image=openstack::Image(
    provider=provider,
    name="{TEST_IMAGE_NAME}",
    uri="{CIRROS_URI}",
    skip_on_deploy=false
)
"""
    )
    created_image = project.get_resource("openstack::Image", name=TEST_IMAGE_NAME)
    assert not created_image.skip_on_deploy

    ctx_dryrun_1 = project.dryrun(created_image)
    assert ctx_dryrun_1.changes

    ctx_deploy_1 = project.deploy(created_image)
    assert ctx_deploy_1.status == inmanta.const.ResourceState.deployed

    matching_images = [
        image for image in glance.images.list() if TEST_IMAGE_NAME == image.name
    ]
    assert len(matching_images) == 1


def test_delete_image(project, glance, cleanup):
    project.compile(
        OPENSTACK_BASE
        + f"""
image=openstack::Image(
    provider=provider,
    name="{TEST_IMAGE_NAME}",
    uri="{CIRROS_URI}",
    skip_on_deploy=false,
    purge_on_delete=true
)
"""
    )
    created_image = project.get_resource("openstack::Image", name=TEST_IMAGE_NAME)

    ctx_deploy_1 = project.deploy(created_image)
    assert ctx_deploy_1.status == inmanta.const.ResourceState.deployed

    matching_images = [
        image for image in glance.images.list() if TEST_IMAGE_NAME == image.name
    ]
    assert len(matching_images) == 1

    project.compile(
        OPENSTACK_BASE
        + f"""
image=openstack::Image(
    provider=provider,
    name="{TEST_IMAGE_NAME}",
    uri="{CIRROS_URI}",
    skip_on_deploy=false,
    purge_on_delete=true,
    purged=true
)
"""
    )

    deleted_image = project.get_resource("openstack::Image", name=TEST_IMAGE_NAME)
    assert deleted_image.purged

    ctx_deploy_2 = project.deploy(deleted_image)
    assert ctx_deploy_2.status == inmanta.const.ResourceState.deployed

    matching_images = [
        image for image in glance.images.list() if TEST_IMAGE_NAME == image.name
    ]
    assert not matching_images


def test_update_image(project, glance, cleanup):
    project.compile(
        OPENSTACK_BASE
        + f"""
image=openstack::Image(
    provider=provider,
    name="{TEST_IMAGE_NAME}",
    uri="{CIRROS_URI}",
    protected=true,
    skip_on_deploy=false,
    purge_on_delete=false,
    metadata = {{
        "test1": "test",
        "test2": "test",
        "test3": "test"
    }}
)
"""
    )
    created_image = project.get_resource("openstack::Image", name=TEST_IMAGE_NAME)

    assert created_image.visibility == "public"
    assert created_image.protected
    assert created_image.metadata == {"test1": "test", "test2": "test", "test3": "test"}

    ctx_deploy_1 = project.deploy(created_image)
    assert ctx_deploy_1.status == inmanta.const.ResourceState.deployed

    matching_images = [
        image for image in glance.images.list() if TEST_IMAGE_NAME == image.name
    ]
    assert len(matching_images) == 1

    # test that non inmanta keys don't get deleted
    glance.images.update(matching_images[0].id, non_inmanta_key="test")

    project.compile(
        OPENSTACK_BASE
        + f"""
image=openstack::Image(
    provider=provider,
    name="{TEST_IMAGE_NAME}",
    uri="{CIRROS_URI}",
    visibility="private",
    protected=false,
    skip_on_deploy=false,
    purge_on_delete=false,
    metadata = {{
        "test1": "test",
        "test2": "not_test"
    }}
)
"""
    )

    updated_image = project.get_resource("openstack::Image", name=TEST_IMAGE_NAME)

    assert updated_image.visibility == "private"
    assert not updated_image.protected

    # test1 remains the same, test2 is updated, 3 is deleted
    assert updated_image.metadata == {
        "test1": "test",
        "test2": "not_test",
    }

    ctx_deploy_2 = project.deploy(updated_image)
    assert ctx_deploy_2.status == inmanta.const.ResourceState.deployed

    images = [image for image in glance.images.list() if TEST_IMAGE_NAME == image.name]
    assert len(matching_images) == 1

    image = images[0]

    assert image.visibility == "private"
    assert not image.protected
    assert image.non_inmanta_key == "test"
    assert image.test1 == "test"
    assert image.test2 == "not_test"
    assert not hasattr(image, "test3")
