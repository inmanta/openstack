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
from keystoneauth1.identity import v3
from keystoneauth1 import session as keystone_session
from keystoneauth1 import exceptions
from keystoneclient.v3 import client as keystone_client
from openstack import connection
from openstack.task_manager import TaskManager, Task
import openstack.task_manager

import random
import string
import functools

PREFIX = "inmanta_unit_test_"




def random_string():
    return "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(10)
    )


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
    auth = v3.Password(
        auth_url=auth_url,
        username=username,
        password=password,
        project_name=tenant,
        user_domain_id="default",
        project_domain_id="default",
    )
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


class NoFuture(object):
    
    def __init__(self, result):
        self._result = result
    
    def result(self, timeout=None):
        return self._result

def nullexecutor(fn, *args, **kwargs):
    result = fn(*args, **kwargs)
    return NoFuture(result)

class TaskManagerBypass(TaskManager):

    def __init__(self, *args, **kwargs):
        pass
    
    def _get_wait(self, tag):
        raise NotImplementedError()

    @property
    def executor(self):
        raise NotImplementedError()

    def start(self):
        pass

    def stop(self):
        pass

    def join(self):
        pass

    def submit_task(self, task):
        task.run()
        ret = task.wait()
        return ret

    def submit_function(
            self, method, name=None, run_async=False, tag=None,
            *args, **kwargs):
        """ Allows submitting an arbitrary method for work.

        :param method: Callable to run in the TaskManager.
        :param str name: Name to use for the generated Task object.
        :param bool run_async: Whether to run this task async or not.
        :param str tag: Named rate-limiting context for the task.
        :param args: positional arguments to pass to the method when it runs.
        :param kwargs: keyword arguments to pass to the method when it runs.
        """
        if run_async:
            payload = functools.partial(
                nullexecutor, method, *args, **kwargs)
            task = Task(
                main=payload, name=name,
                run_async=run_async,
                tag=tag)
        else:
            task = Task(
                main=method, name=name,
                tag=tag,
                *args, **kwargs)
        return self.submit_task(task)

    def submit_function_async(self, method, name=None, *args, **kwargs):
        """ Allows submitting an arbitrary method for async work scheduling.

        :param method: Callable to run in the TaskManager.
        :param str name: Name to use for the generated Task object.
        :param args: positional arguments to pass to the method when it runs.
        :param kwargs: keyword arguments to pass to the method when it runs.
        """
        return self.submit_function(
            method, name=name, run_async=True, *args, **kwargs)

    def pre_run_task(self, task):
        '''Callback when task enters the task queue

        :param task: the task

        Intended to be overridden by child classes to track task
        progress.
        '''
        self._log.debug(
            "Manager %s running task %s", self.name, task.name)

    def run_task(self, task):
        # Never call task.wait() in the run_task call stack because we
        # might be running in another thread.  The exception-shifting
        # code is designed so that caller of submit_task (which may be
        # in a different thread than this run_task) gets the
        # exception.
        #
        # Note all threads go through the threadpool, so this is an
        # async call.  submit_task will wait() for the final result.
        task.run()

    def post_run_task(self, elapsed_time, task):
        '''Callback at task completion

        :param float elapsed_time: time in seconds between task entering
            queue and finishing
        :param task: the task

        This function is intended to be overridden by child classes to
        monitor task runtimes.
        '''
        self._log.debug(
            "Manager %s ran task %s in %ss",
            self.name, task.name, elapsed_time)
 
#ugly monkey patch to stop openstacksdk from leaking threads
openstack.task_manager.TaskManager = TaskManagerBypass

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
        self._connection = None

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
    def connection(self):
        if self._connection is None:
            self._connection = connection.Connection(
                session=self.session, identity_interface="public", identity_api_version="3.0"
            )
        return self._connection

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

    def __init__(
        self, tester: "OpenstackTester", super_admin: User, admin: User, user: User, project_object
    ):
        self._user = user
        self._admin = admin
        self._super_admin = super_admin

        self.project_object = project_object

    @property
    def project_id(self):
        return self.project_object.id

    def get_resource_name(self, name: str) -> str:
        return PREFIX + name

    def grant(self, user: User, role="member"):
        # don't include domain, as it will fail when user and project are not in the same domain
        self._super_admin.connection.grant_role(
            role, user=user.id, project=self.project_object.id
        )

    def find_network(self, name: str):
        project_id = self.project_object.id
        inproject = self._admin.connection.network.find_network(
            name, project_id=project_id)
        return inproject

    def assert_network(self, name: str):
        return self.find_network(name)

    def create_network(self, name: str, double=False):
        out = self.find_network(name)
        if out is not None and not double:
            return out
        return self._admin.connection.network.create_network(
            project_id=self.project_object.id,
            name=name)

    def find_subnet(self, name: str) -> None:
        project_id = self.project_object.id
        inproject = self._admin.connection.network.find_subnet(
            name, project_id=project_id)
        return inproject

    def create_subnet(self, name: str, network_id: str,ip_version:int=4, cidr="192.168.50.1/24"):
        out = self.find_subnet(name)
        if out is not None:
            return out
        return self._admin.connection.network.create_subnet(
            project_id=self.project_object.id,
            name=name,
            network_id=network_id,
            ip_version=ip_version,
            cidr=cidr)

class OpenstackTester(object):
    """
        Object that provides access to an openstack and performs cleanup
    """

    def __init__(self, auth_url, username, password, tenant, domain):
        self._projects = {}
        self._admin = User(auth_url, username, password, tenant, domain)

    @property
    def admin(self):
        return self._admin

    def get_resource_name(self, name: str) -> str:
        return PREFIX + name

    def get_shared_project(self) -> Project:
        return self.get_project("shared")

    def get_shared_project_d2(self) -> Project:
        return self.get_project("shared", domain="inmanta-test-domain1")

    def get../../../.virtualenvs/inmanta-openstack/lib/python3.6/site-packages/openstack/connection.py:305:
ain="default"):
        """../../../.virtualenvs/inmanta-openstack/lib/python3.6/site-packages/openstack/connection.py:305:

            Get a project with the given name (will be prefixed!). If it already exists a reference is returned
        """
        key = domain + "|" + name
        if key in self._projects:
            return self._projects[key]

        prefixed_tenant = self.get_resource_name(name)

        # domain
        domainobject = self.admin.connection.identity.find_domain(domain)
        if domainobject is None:
            domainobject = self.admin.connection.create_domain(
                domain, description="Unit test domain"
            )
        assert domainobject is not None

        # project
        projectobject = self.admin.connection.identity.find_project(
            prefixed_tenant, domain_id=domainobject.id
        )
        clean_project = False
        if projectobject is not None:
            print("Found project ", domain, prefixed_tenant)
            clean_project = True
        else:
            print("Created project ", domain, prefixed_tenant)
            projectobject = self.admin.connection.identity.create_project(
                name=prefixed_tenant,
                description="Unit test project",
                enabled=True,
                domain_id=domainobject.id,
            )

        # users
        def grant(user_id, role):
            # don't include domain, as it will fail when user and project are not in the same domain
            self.admin.connection.grant_role(
                role, user=user_id, project=projectobject.id
            )

        def make_user_if_required(name):
            user = self._admin.connection.get_user(
                name, domain_id=domainobject.id)
            passwd = name

            userobject = User(
                auth_url=self.admin._auth_url,
                username=name,
                password=passwd,
                tenant=projectobject.name,
                domain=domainobject.name,
            )

            if user is not None:
                userobject.id = user.id
                return user, userobject

            user = self._admin.connection.create_user(
                name,
                password=passwd,
                email="xx@example.org",
                default_project=projectobject.id,
                enabled=True,
                domain_id=domainobject.id,
                description="testuser"
            )
            assert user is not None
            userobject.id = user.id
            return (
                user,
                userobject
            )

        grant(self._admin.connection.current_user_id, "admin")
        admin, admin_user = make_user_if_required(prefixed_tenant + "admin")
        grant(admin.id, "admin")
        user, user_user = make_user_if_required(prefixed_tenant + "user")
        grant(user.id, "member")

        prj = Project(self,
                      project_object=projectobject,
                      super_admin=self.admin,
                      admin=admin_user,
                      user=user_user)

        if clean_project:
            self.clean_project(prj)

        self._projects[key] = prj
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
                    self.clean_project(
                        prj) if prj.project_object is not None else True
                )
                if prj.project_object is not None and done:
                    prj._super_admin.connection.delete_project(
                        prj.project_object.id)
                    prj.project_object = None

                if not done:
                    ready = False

            count += 1

    def clean_project(self, project):
        """
            Clean all the resource in the given project
        """
        conn = project._super_admin.connection

        project_id = project.project_object.id
        # for server in conn.compute.servers(project_id=project_id, all_tenants=True):
        #     print("Found server:",server)
        #     conn.compute.delete_server(server)

        # for kp in project.nova.keypairs.list():
        #     kp.delete()

        # for hp in project.neutron.list_ports()["ports"]:
        #     if hp["tenant_id"] == project_id:
        #         project.neutron.delete_port(hp["id"])

        subnets = conn.network.subnets(project_id=project_id)
        for subnet in subnets:
            conn.network.delete_subnet(subnet.id)

        networks = conn.network.networks(project_id=project_id)
        for network in networks:
            conn.network.delete_network(network.id)

        return True


@pytest.fixture(scope="function")
def openstack(request):
    ost = OpenstackTester(
        auth_url=os.environ["OS_AUTH_URL"],
        username=os.environ["OS_USERNAME"],
        password=os.environ["OS_PASSWORD"],
        tenant=os.environ["OS_PROJECT_NAME"],
        domain="default",
    )

    yield ost
    if not request.config.getoption("--noclean"):
        ost.cleanup()
