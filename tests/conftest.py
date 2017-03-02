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
from keystoneclient.v3 import client as keystone_client


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
