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
from keystoneclient.v3 import client


def test_project(project, keystone):
    try:
        project_name = "inmanta_unit_test"
        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name="%s", description="", enabled=true)
            """
            % project_name
        )

        n1 = project.get_resource("openstack::Project", name=project_name)
        ctx = project.deploy(n1)
        assert ctx.status == inmanta.const.ResourceState.deployed

        keystone.projects.find(name=project_name)

        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name="%s", description="", enabled=true, purged=true)
            """
            % project_name
        )

        n1 = project.get_resource("openstack::Project", name=project_name)
        ctx = project.deploy(n1)
        assert ctx.status == inmanta.const.ResourceState.deployed

        with pytest.raises(Exception):
            keystone.projects.find(name=project_name)

    finally:
        try:
            keystone.projects.find(name=project_name).delete()
        except Exception:
            pass


def test_user(project, keystone):
    try:
        user_name = "inmanta_unit_test"
        pw = "12345678"

        # create the user
        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    openstack::User(provider=p, name="%s", email="abc", password="%s")
            """
            % (user_name, pw)
        )

        n1 = project.get_resource("openstack::User", name=user_name)
        ctx = project.deploy(n1)
        assert ctx.status == inmanta.const.ResourceState.deployed

        keystone.users.find(name=user_name)
        c = client.Client(
            auth_url=os.environ["OS_AUTH_URL"], username=user_name, password=pw
        )
        assert c.authenticate()

        # change the password
        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    openstack::User(provider=p, name="%s", email="abc", password="%s")
            """
            % (user_name, user_name)
        )

        n1 = project.get_resource("openstack::User", name=user_name)
        ctx = project.deploy(n1)
        assert ctx.status == inmanta.const.ResourceState.deployed

        # c = client.Client(auth_url=os.environ["OS_AUTH_URL"], username=user_name, password=user_name)
        # assert c.authenticate()

        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    openstack::User(provider=p, name="%s", email="abc", purged=true)
            """
            % user_name
        )

        n1 = project.get_resource("openstack::User", name=user_name)
        ctx = project.deploy(n1)
        assert ctx.status == inmanta.const.ResourceState.deployed

        with pytest.raises(Exception):
            keystone.users.find(name=user_name)

    finally:
        try:
            keystone.user.find(name=user_name).delete()
        except Exception:
            pass


def test_role(project, keystone):
    try:
        user_name = "inmanta_unit_test"
        role_name = "Member"

        # create the user, project and role
        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name="%(name)s", description="", enabled=true)
    user = openstack::User(provider=p, name="%(name)s", email="abc", password="")
    openstack::Role(role="%(role)s", project=project, user=user)
            """
            % {"name": user_name, "role": role_name}
        )

        u = project.get_resource("openstack::User", name=user_name)
        ctx = project.deploy(u)
        assert ctx.status == inmanta.const.ResourceState.deployed

        p = project.get_resource("openstack::Project", name=user_name)
        ctx = project.deploy(p)
        assert ctx.status == inmanta.const.ResourceState.deployed

        r = project.get_resource("openstack::Role")
        ctx = project.deploy(r)
        assert ctx.status == inmanta.const.ResourceState.deployed

        pr = keystone.projects.find(name=user_name)
        user = keystone.users.find(name=user_name)
        role = keystone.roles.find(name=role_name)

        keystone.roles.check(role=role, user=user, project=pr)

        # remove the role
        # create the user, project and role
        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    project = openstack::Project(provider=p, name="%(name)s", description="", enabled=true)
    user = openstack::User(provider=p, name="%(name)s", email="abc", password="")
    openstack::Role(role="%(role)s", project=project, user=user, purged=true)
            """
            % {"name": user_name, "role": role_name}
        )

        r = project.get_resource("openstack::Role")
        ctx = project.deploy(r)
        assert ctx.status == inmanta.const.ResourceState.deployed

        with pytest.raises(Exception):
            keystone.roles.check(role=role, user=user, project=pr)

    finally:
        try:
            keystone.projects.find(name=user_name).delete()
        except Exception:
            pass

        try:
            keystone.users.find(name=user_name).delete()
        except Exception:
            pass

        try:
            keystone.roles.find(name=role_name).delete()
        except Exception:
            pass


def test_service_endpoints(project, keystone):
    try:
        service_name = "test_server"

        # create
        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    s = openstack::Service(name="%(name)s", type="testing", description="Testing!!!!", provider=p)
    openstack::EndPoint(region="RegionOne", service=s, public_url="http://localhost:1234", admin_url="http://localhost:1234",
                        internal_url="http://localhost:1234")
            """
            % {"name": service_name}
        )

        s = project.get_resource("openstack::Service")
        ctx = project.deploy(s)
        assert ctx.status == inmanta.const.ResourceState.deployed

        service = keystone.services.find(name=service_name)
        assert service.description == s.description

        e = project.get_resource("openstack::EndPoint")
        ctx = project.deploy(e)
        assert ctx.status == inmanta.const.ResourceState.deployed

        eps = keystone.endpoints.list(service=service)
        assert len(eps) == 3

        # update
        project.compile(
            """
    import unittest
    import openstack

    tenant = std::get_env("OS_PROJECT_NAME")
    p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                            password=std::get_env("OS_PASSWORD"), tenant=tenant)
    s = openstack::Service(name="%(name)s", type="testing", description="Testing!", provider=p)
    openstack::EndPoint(region="RegionOne", service=s, public_url="http://localhost:12345", admin_url="http://localhost:12345",
                        internal_url="http://localhost:12345")
            """
            % {"name": service_name}
        )

        s = project.get_resource("openstack::Service")
        ctx = project.deploy(s)
        assert ctx.status == inmanta.const.ResourceState.deployed

        service = keystone.services.find(name=service_name)
        assert service.description == s.description

        e = project.get_resource("openstack::EndPoint")
        ctx = project.deploy(e)
        assert ctx.status == inmanta.const.ResourceState.deployed

        eps = keystone.endpoints.list(service=service)
        assert len(eps) == 3
        for ep in eps:
            assert ep.url[-1] == "5"

    finally:
        try:
            service = keystone.services.find(name=service_name)
            eps = keystone.endpoints.list(service=service)
            for ep in eps:
                ep.delete()

            service.delete()
        except Exception:
            pass
