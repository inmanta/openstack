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
import os

import inmanta
import pytest


def get_test_flavor(nova):
    flavors = nova.flavors.list()
    for flavor in flavors:
        if flavor.name == "test-flavor":
            return flavor


# Flavors are not tied to projects, so need seperate cleanup
def cleanup_flavor(nova):
    flavors = nova.flavors.list()
    for flavor in flavors:
        if flavor.name == "test-flavor":
            nova.flavors.delete(flavor)


@pytest.fixture()
def cleanup(nova):
    cleanup_flavor(nova)
    yield
    cleanup_flavor(nova)


def test_flavor(project, nova, cleanup):
    # test create
    flavor_name = "test-flavor"
    project.compile(
        f"""
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
provider = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)

flavor=openstack::Flavor(
    provider=provider,
    name="{flavor_name}",
    ram=1024,
    vcpus=4,
    disk=10,
    extra_specs={{
        "quota:cpu_quota": 10000
    }}
)
"""
    )
    created_flavor = project.get_resource("openstack::Flavor", name=flavor_name)
    assert created_flavor
    assert created_flavor.ram == 1024
    assert created_flavor.vcpus == 4
    assert created_flavor.disk == 10

    assert created_flavor.flavor_id is None
    assert created_flavor.ephemeral == 0
    assert created_flavor.swap == 0
    assert created_flavor.rxtx_factor == 1.0
    assert created_flavor.is_public
    assert created_flavor.extra_specs == {"quota:cpu_quota": "10000"}

    assert created_flavor.admin_user == os.environ.get("OS_USERNAME")
    assert created_flavor.admin_password == os.environ.get("OS_PASSWORD")
    assert created_flavor.admin_tenant == os.environ.get("OS_PROJECT_NAME")
    assert created_flavor.auth_url == os.environ.get("OS_AUTH_URL")

    ctx_dryrun_1 = project.dryrun(created_flavor)
    assert ctx_dryrun_1.changes

    ctx_deploy_1 = project.deploy(created_flavor)
    assert ctx_deploy_1.status == inmanta.const.ResourceState.deployed

    ctx_dryrun_2 = project.dryrun(created_flavor)
    assert not ctx_dryrun_2.changes

    # test update 1: extra_specs update
    project.compile(
        f"""
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
provider = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)

flavor=openstack::Flavor(
    provider=provider,
    name="{flavor_name}",
    ram=1024,
    vcpus=4,
    disk=10,
    extra_specs={{
        "quota:cpu_period": 20000,
        "hw:watchdog_action": "reset"
    }}
)
"""
    )
    updated_flavor = project.get_resource("openstack::Flavor", name=flavor_name)
    assert updated_flavor.extra_specs == {
        "quota:cpu_period": "20000",
        "hw:watchdog_action": "reset",
    }

    ctx_deploy_3 = project.deploy(updated_flavor)
    assert ctx_deploy_3.status == inmanta.const.ResourceState.deployed

    ctx_dryrun_3 = project.dryrun(updated_flavor)
    assert not ctx_dryrun_3.changes

    # test update 2: illegal update
    project.compile(
        f"""
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
provider = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)

flavor=openstack::Flavor(
    provider=provider,
    name="{flavor_name}",
    ram=2048,
    vcpus=4,
    disk=10,
    extra_specs={{
        "quota:cpu_period": 20000,
        "hw:watchdog_action": "reset"
    }}
)
"""
    )
    updated_flavor = project.get_resource("openstack::Flavor", name=flavor_name)
    assert updated_flavor.ram == 2048

    ctx_deploy_4 = project.deploy(updated_flavor)
    assert ctx_deploy_4.status == inmanta.const.ResourceState.failed

    # test delete
    project.compile(
        f"""
import openstack

tenant = std::get_env("OS_PROJECT_NAME")
provider = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
flavor=openstack::Flavor(
    provider=provider,
    name="{flavor_name}",
    ram=1024,
    vcpus=4,
    disk=10,
    extra_specs={{
        "quota:cpu_period": 20000,
        "hw:watchdog_action": "reset"
    }},
    purged=true
)
"""
    )
    deleted_flavor = project.get_resource("openstack::Flavor", name=flavor_name)
    assert deleted_flavor.purged

    ctx_deploy_4 = project.deploy(deleted_flavor)
    assert ctx_deploy_4.status == inmanta.const.ResourceState.deployed

    ctx_dryrun_5 = project.dryrun(deleted_flavor)
    assert not ctx_dryrun_5.changes
