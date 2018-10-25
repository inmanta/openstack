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


class Project(object):
    """
        An project instance
    """
    def __init__(self, tester: "OpenstackTester", auth_url: str, username: str, password: str, tenant: str, domain:str):
        self._auth_url = auth_url
        self._username = username
        self._password = password
        self._tenant = tenant
        self._domain = domain

        self._session_obj = None
        self._nova = None
        self._keystone = None
        self._neutron = None
        self.project_object = None

    @property
    def session(self):
        if self._session_obj is None:
            auth = v3.Password(auth_url=self._auth_url, username=self._username, password=self._password,
                               project_name=self._tenant, user_domain_name=self._domain, project_domain_name=self._domain)
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

    def get_resource_name(self, name: str) -> str:
        return PREFIX + name

    def assert_network(self, name: str) -> None:
        project_id = self.project_object.id
        inproject = self.neutron.list_networks(project_id=project_id)["networks"]
        for net in inproject:
            if net["name"] == name:
                return

        print(inproject)
        assert False, "could not find %s in %s"%(name, inproject)

    def assert_subnet(self, name: str) -> None:
        project_id = self.project_object.id
        inproject = self.neutron.list_subnets(project_id=project_id)["subnets"]
        for net in inproject:
            if net["name"] == name:
                return

        print(inproject)
        assert False, "could not find %s in %s"%(name, inproject)


class OpenstackTester(object):
    """
        Object that provides access to an openstack and performs cleanup
    """
    def __init__(self, auth_url, username, password, tenant, domain):
        self._projects = {}
        self._admin = Project(self, auth_url, username, password, tenant, domain)
    
    @property
    def admin(self):            
        return self._admin

    def get_resource_name(self, name: str) -> str:
        return PREFIX + name

    def get_project(self, name):
        """
            Get a project with the given name (will be prefixed!). If it already exists a reference is returned
        """
        if name in self._projects:
            return self._projects[name]

        prefixed_tenant = self.get_resource_name(name)
        auth_url = self.admin._auth_url
        username = self.admin._username
        password = self.admin._password
        domain = self.admin._domain
        prj = Project(self, auth_url, username, password, prefixed_tenant, domain)

        self._projects[name] = prj

        domainobject = self.admin.keystone.domains.find(name=domain)
        # create the project and add the user to that project
        try:
            project = self.admin.keystone.projects.find(name=prefixed_tenant, domain_id=domainobject.id)
            prj.project_object = project
            print("Found project ", self.admin._domain, prefixed_tenant, project)
            self.clean_project(prj)
        except exceptions.http.NotFound:
            print("Creating project ", self.admin._domain, prefixed_tenant)
            # create the project
            project = self.admin.keystone.projects.create(prefixed_tenant, description="Unit test project", enabled=True,
                                                          domain=domainobject)
            prj.project_object = project

        # get the member role
        role = self.admin.keystone.roles.find(name="admin")
        user = self.admin.keystone.users.find(name=username)
        self.admin.keystone.roles.grant(user=user, role=role, project=project)

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
def openstack():
    ost = OpenstackTester(
            auth_url = os.environ["OS_AUTH_URL"],
            username = os.environ["OS_USERNAME"],
            password = os.environ["OS_PASSWORD"],
            tenant = os.environ["OS_PROJECT_NAME"],
            domain = "default")

    yield ost

    ost.cleanup()