"""
    Copyright 2017 Inmanta

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
import pytest

from neutronclient.neutron import client as neutron_client
from novaclient import client as nova_client
from keystoneclient.auth.identity import v3
from keystoneauth1 import session as keystone_session
from keystoneauth1 import exceptions
from keystoneclient.v3 import client as keystone_client


PREFIX = "inmanta_unit_test_"

def pytest_addoption(parser):
    parser.addoption(
        "--noclean", action="store_true", default=False, help="leave tenants after tests"
    )

@pytest.fixture(scope="session")
def session():
    auth_url = os.environ["OS_AUTH_URL"]
    username = os.environ["OS_USERNAME"]
    password = os.environ["OS_PASSWORD"]
    tenant = os.environ["OS_PROJECT_NAME"]
    auth = v3.Password(auth_url=auth_url, username=username, password=password, project_name=tenant,
                       user_domain_id="default", project_domain_id="default")
    sess = keystone_session.Session(auth=auth)
    yield sess

@pytest.fixture(scope="session")
def nova(session):
    yield nova_client.Client("2", session=session)


@pytest.fixture(scope="session")
def neutron(session):
    yield neutron_client.Client("2.0", session=session)


@pytest.fixture(scope="session")
def keystone(session):
    yield keystone_client.Client(session=session)


class User(object):
    def __init__(
        self, auth_url: str, username: str, password: str, tenant: str, domain: str
    ):
        self._auth_url = auth_url
        self._username = username
        self._password = password
        self._tenant = tenant
        self._domain = domain

        self._session_obj = None
        self._nova = None
        self._neutron = None
        self._keystone = None

        self.id = None

    @property
    def session(self):
        if self._session_obj is None:
            auth = v3.Password(
                auth_url=self._auth_url,
                username=self._username,
                password=self._password,
                project_name=self._tenant,
                user_domain_name=self._domain,
                project_domain_name=self._domain,
            )
            self._session_obj = keystone_session.Session(auth=auth)
        return self._session_obj

    @property
    def nova(self):
        if self._nova is None:
            self._nova = nova_client.Client("2", session=self.session)
        return self._nova

    @property
    def neutron(self):
        if self._neutron is None:
            self._neutron = neutron_client.Client("2.0", session=self.session)
        return self._neutron

    @property
    def keystone(self):
        if self._keystone is None:
            self._keystone = keystone_client.Client(session=self.session)
        return self._keystone


    def snippet(self):
        return """openstack::Provider(
                        name="%(domain)s%(project)s%(username)s", 
                        connection_url="%(url)s", 
                        username="%(username)s",
                        password="%(pass)s", 
                        tenant="%(project)s",
                        project_domain_name="%(domain)s",
                        user_domain_name="%(domain)s")""" % {
            "domain": self._domain,
            "project": self._tenant,
            "username": self._username,
            "url": self._auth_url,
            "pass": self._password
        }


class Project(object):
    """
        An project instance
    """
    def __init__(self, tester: "OpenstackTester", admin: User, user: User, project_object):
        self._user = user
        self._admin = admin
        self.project_object = project_object

    @property
    def session(self):
        return self.user.session

    @property
    def nova(self):
        return self.user.nova

    @property
    def neutron(self):
        return self.user.neutron

    @property
    def keystone(self):
        return self.user.keystone

    def get_resource_name(self, name: str) -> str:
        return PREFIX + name


class OpenstackTester(object):
    """
        Object that provides access to an openstack and performs cleanup
    """
    def __init__(self):
        self._projects = {}
        self._admin = None

    @property
    def admin(self):
        if self._admin is None:
            auth_url = os.environ["OS_AUTH_URL"]
            username = os.environ["OS_USERNAME"]
            password = os.environ["OS_PASSWORD"]
            tenant = os.environ["OS_PROJECT_NAME"]
            self._admin = User(auth_url, username, password, tenant, "default")
        return self._admin

    def get_resource_name(self, name: str) -> str:
        return PREFIX + name

    def get_shared_project(self) -> Project:
        return self.get_project("shared")

    def get_shared_project_d2(self) -> Project:
        return self.get_project("shared", domain="inmanta-test-domain1")

    def get_project(self, name, domain="default"):
        """
            Get a project with the given name (will be prefixed!). If it already exists a reference is returned
        """
        key = domain + "|" + name
        if key in self._projects:
            return self._projects[key]

        prefixed_tenant = self.get_resource_name(name)
        auth_url = os.environ["OS_AUTH_URL"]
        username = os.environ["OS_USERNAME"]
        password = os.environ["OS_PASSWORD"]
        

        # domain
        try:
            domainobject = self.admin.keystone.domains.find(name=domain)
        except exceptions.http.NotFound:
            domainobject = self.admin.keystone.domains.create(
                domain, description="Unit test domain"
            )
        assert domainobject is not None
        print("D", domainobject)

        # create the project and add the user to that project
        clean_project = False
        try:
            project = self.admin.keystone.projects.find(name=prefixed_tenant, domain_id=domainobject.id)
            print("Found project ", domain, prefixed_tenant)
            clean_project = True
        except exceptions.http.NotFound:
            # create the project
            project = self.admin.keystone.projects.create(prefixed_tenant, description="Unit test project", enabled=True,
                                                          domain=domainobject.id)
            prj.project_object = project

        # users
        def grant(user_id, role):
            # don't include domain, as it will fail when user and project are not in the same domain
            role = self.admin.keystone.roles.find(name=role)
            self.admin.keystone.roles.grant(
                role, user=user_id, project=project.id
            )

        def make_user_if_required(name):
            passwd = name
            userobject = User(
                auth_url=self.admin._auth_url,
                username=name,
                password=passwd,
                tenant=project.name,
                domain=domainobject.name,
            )
            try:
                user = self.admin.keystone.users.find(name=name, domain_id=domainobject.id)
                userobject.id = user.id
                return user, userobject
            except exceptions.http.NotFound:
                user = self.admin.keystone.users.create(
                    name,
                    password=passwd,
                    email="xx@example.org",
                    default_project=project.id,
                    enabled=True,
                    domain=domainobject.id,
                    description="testuser"
                )
                assert user is not None
                userobject.id = user.id
                return (
                    user,
                    userobject
                )



        # add admin role to admin
        role = self.admin.keystone.roles.find(name="admin")
        user = self.admin.keystone.users.find(name=username)
        self.admin.keystone.roles.grant(user=user, role=role, project=project)

        #create user with user role
        user, user_user = make_user_if_required(prefixed_tenant + "user")
        grant(user.id, "member")



        prj = Project(self,
                project_object=project,
                admin=self.admin,
                user=user_user)
        self._projects[key] = prj

        if clean_project:
            self.clean_project(prj)

        return prj

    def cleanup(self):
        """
            There might be dependencies over tenants. The "easiest" way is trial and error delete in a loop.
        """
        count = 0
        ready = False
        while count < 10 and not ready:
            ready = True
            for prj in self._projects.values():
                done = self.clean_project(prj) if prj.project_object is not None else True
                if prj.project_object is not None and done:
                    prj.project_object.delete()
                    prj.project_object = None

                if not done:
                    ready = False

            count += 1

    def clean_project(self, project):
        """
            Clean all the resource in the given project
        """
        try:
            project_id = project.project_object.id
            for server in project.nova.servers.list():
                server.delete()

            for kp in project.nova.keypairs.list():
                kp.delete()

            for hp in project.neutron.list_ports()["ports"]:
                if hp["tenant_id"] == project_id:
                    project.neutron.delete_port(hp["id"])

            subnets = project.neutron.list_subnets()["subnets"]
            for subnet in subnets:
                if subnet["tenant_id"] == project_id:
                    project.neutron.delete_subnet(subnet["id"])

            networks = project.neutron.list_networks()["networks"]
            for network in networks:
                if network["tenant_id"] == project_id:
                    project.neutron.delete_network(network["id"])

            return True
        except Exception:
            return False

@pytest.fixture(scope="function")
def openstack(request):
    ost = OpenstackTester()

    yield ost

    if not request.config.getoption("--noclean"):
        ost.cleanup()
