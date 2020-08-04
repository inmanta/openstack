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
import logging
import os
import time
from typing import Callable, Optional

import pytest
import requests
from glanceclient.v2 import client as glance_client
from keystoneauth1 import exceptions
from keystoneauth1 import session as keystone_session
from keystoneclient.auth.identity import v3
from keystoneclient.v3 import client as keystone_client
from neutronclient.neutron import client as neutron_client
from novaclient import client as nova_client
from novaclient.v2.servers import Server

LOGGER = logging.getLogger(__name__)

PREFIX = "inmanta_unit_test_"


class PackStackVM:

    PACKSTACK_IP: str = "192.168.26.18"
    IMAGE_NAME: str = "packstack-snapshot"
    FLAVOR_NAME: str = "c4m16d20"
    NETWORK_ID: str = "14376e55-8447-4aa9-9b35-b8f922eadbd6"
    PACKSTACK_VM_NAME: str = "packstack"

    def __init__(self) -> None:
        auth_url = self._get_environment_variable("INFRA_SETUP_OS_AUTH_URL")
        username = self._get_environment_variable("INFRA_SETUP_OS_USERNAME")
        password = self._get_environment_variable("INFRA_SETUP_OS_PASSWORD")
        tenant = self._get_environment_variable("INFRA_SETUP_OS_PROJECT_NAME")
        session = create_session(auth_url, username, password, tenant)
        self._nova_client = nova_client.Client("2", session=session)
        self._neutron_client = neutron_client.Client("2.0", session=session)
        self._glance_client = glance_client.Client(session=session)
        self._server: Optional[Server] = None

    def _get_environment_variable(self, env_var_name) -> str:
        env_var = os.getenv(env_var_name)
        if env_var is None:
            raise Exception(f"Environment variable {env_var_name} should be set")
        return env_var

    def _delete_previous_instances(self) -> None:
        for server in self._nova_client.servers.list(search_opts={"name": self.PACKSTACK_VM_NAME}):
            server.delete()

    def create(self) -> None:
        if self._server is not None:
            raise Exception("Server was already created")
        try:
            self._delete_previous_instances()
            self._create_vm()
            self._disable_port_security()
            LOGGER.info("Waiting until packstack is up")
            self._wait_until(
                self._is_packstart_up,
                timeout_in_sec=1800,
                timeout_message="Packstack didn't come online after 1800sec",
            )
        except Exception as e:
            if self._server is not None:
                self.delete()
            raise e

    def _create_vm(self) -> None:
        LOGGER.info("Creating packstack VM")
        path_to_userdata_file = os.path.join(
            os.path.dirname(__file__), "..", "ci", "user_data"
        )
        with open(path_to_userdata_file, "r") as f:
            user_data = f.read()
        flavor_id = self._nova_client.flavors.find(name=self.FLAVOR_NAME).id
        image_ids = [
            image.id
            for image in self._glance_client.images.list()
            if image["name"] == self.IMAGE_NAME
        ]
        if not image_ids:
            raise Exception(f"Image with name {self.IMAGE_NAME} not found")
        image_id = image_ids[0]
        self._server = self._nova_client.servers.create(
            name=self.PACKSTACK_VM_NAME,
            flavor=flavor_id,
            userdata=user_data,
            nics=[{"net-id": self.NETWORK_ID}],
            image=image_id,
            config_drive=True,
        )
        LOGGER.info("Waiting until the VM enters the active state")
        self._wait_until(
            self._is_vm_in_active_state,
            timeout_in_sec=180,
            timeout_message="VM didn't get into the active state in 180sec",
        )

    def _disable_port_security(self) -> None:
        LOGGER.info("Disabling port security")
        ports = self._neutron_client.list_ports(device_id=self._server.id)
        assert len(ports["ports"]) > 0
        port = ports["ports"][0]
        self._neutron_client.update_port(
            port=port["id"],
            body={"port": {"port_security_enabled": False, "security_groups": None}},
        )

    def delete(self) -> None:
        if self._server is None:
            return
        LOGGER.info("Deleting packstack VM")
        self._server.delete()
        self._server = None

    def _is_vm_in_active_state(self) -> bool:
        vm = self._nova_client.servers.get(self._server.id)
        vm_state = getattr(vm, "OS-EXT-STS:vm_state")
        return vm_state == "active"

    def _is_packstart_up(self) -> bool:
        try:
            for port in [8774, 5000, 9292, 9696, 8778, 8776]:
                requests.get(f"http://{self.PACKSTACK_IP}:{port}", timeout=5)
        except requests.RequestException:
            LOGGER.debug("Port %d not up", port)
            return False
        return True

    def _wait_until(
        self, func: Callable[[], bool], timeout_in_sec: int, timeout_message: str
    ) -> None:
        timeout_timestamp = time.time() + timeout_in_sec
        while not func() and time.time() < timeout_timestamp:
            time.sleep(5)
        if not func:
            raise Exception(timeout_message)


@pytest.fixture(
    scope="session",
    autouse=os.getenv("INMANTA_TEST_INFRA_SETUP", default="false").lower() == "true",
)
def create_packstack_vm():
    packstack_vm = PackStackVM()
    packstack_vm.create()
    yield
    packstack_vm.delete()


@pytest.fixture(scope="session")
def session():
    auth_url = os.environ["OS_AUTH_URL"]
    username = os.environ["OS_USERNAME"]
    password = os.environ["OS_PASSWORD"]
    tenant = os.environ["OS_PROJECT_NAME"]
    yield create_session(auth_url, username, password, tenant)


def create_session(
    auth_url: str, username: str, password: str, tenant: str
) -> keystone_session.Session:
    auth = v3.Password(
        auth_url=auth_url,
        username=username,
        password=password,
        project_name=tenant,
        user_domain_id="default",
        project_domain_id="default",
    )
    return keystone_session.Session(auth=auth)


@pytest.fixture(scope="session")
def nova(session):
    yield nova_client.Client("2", session=session)


@pytest.fixture(scope="session")
def neutron(session):
    yield neutron_client.Client("2.0", session=session)


@pytest.fixture(scope="session")
def keystone(session):
    yield keystone_client.Client(session=session)


@pytest.fixture(scope="session")
def glance(session):
    yield glance_client.Client(session=session)


class Project(object):
    """
        An project instance
    """

    def __init__(
        self,
        tester: "OpenstackTester",
        auth_url: str,
        username: str,
        password: str,
        tenant: str,
    ):
        self._auth_url = auth_url
        self._username = username
        self._password = password
        self._tenant = tenant
        self._session_obj = None
        self._nova = None
        self._keystone = None
        self._neutron = None
        self._glance = None
        self.project_object = None

    @property
    def session(self):
        if self._session_obj is None:
            auth = v3.Password(
                auth_url=self._auth_url,
                username=self._username,
                password=self._password,
                project_name=self._tenant,
                user_domain_id="default",
                project_domain_id="default",
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

    @property
    def glance(self):
        if self._glance is None:
            self._glance = glance_client.Client(session=self.session)

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
            self._admin = Project(self, auth_url, username, password, tenant)
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
        auth_url = os.environ["OS_AUTH_URL"]
        username = os.environ["OS_USERNAME"]
        password = os.environ["OS_PASSWORD"]
        prj = Project(self, auth_url, username, password, prefixed_tenant)

        self._projects[name] = prj

        # create the project and add the user to that project
        try:
            project = self.admin.keystone.projects.find(name=prefixed_tenant)
            prj.project_object = project

            self.clean_project(prj)
        except exceptions.http.NotFound:
            # create the project
            project = self.admin.keystone.projects.create(
                prefixed_tenant,
                description="Unit test project",
                enabled=True,
                domain="default",
            )
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
                done = (
                    self.clean_project(prj) if prj.project_object is not None else True
                )
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

            for image in project.glance.images.list():
                project.glance.delete(image.id)

            return True
        except Exception:
            return False


@pytest.fixture(scope="function")
def openstack():
    ost = OpenstackTester()

    yield ost

    ost.cleanup()
