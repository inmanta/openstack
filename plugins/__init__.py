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

import datetime
import logging
import math
import os
import time
import traceback
from collections import defaultdict
from typing import Dict, Optional, Tuple

import keystoneauth1.exceptions
import novaclient.exceptions
from glanceclient import client as glance_client
from glanceclient import exc as glance_exceptions
from inmanta import ast, resources
from inmanta.agent import handler
from inmanta.agent.handler import (
    CRUDHandler,
    InvalidOperation,
    ResourcePurged,
    SkipResource,
    cache,
    provider,
)
from inmanta.execute import proxy
from inmanta.execute.util import Unknown
from inmanta.export import dependency_manager
from inmanta.plugins import PluginException, plugin
from inmanta.resources import ManagedResource, PurgeableResource, resource
from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneclient.v3 import client as keystone_client
from neutronclient.common import exceptions
from neutronclient.neutron import client as neutron_client
from novaclient import client as nova_client
from novaclient.v2 import flavors

try:
    from keystoneclient.exceptions import NotFound
except ImportError:
    from keystoneclient.openstack.common.apiclient.exceptions import NotFound

# silence a logger
# loud_logger = logging.getLogger("requests.packages.urllib3.connectionpool")
# loud_logger.propagate = False


LOGGER = logging.getLogger(__name__)


IMAGES = {}
FIND_IMAGE_RESULT = {}


@plugin
def find_image(
    provider: "openstack::Provider", os: "std::OS", name: "string" = None
) -> "string":
    """
    Search for an image that matches the given operating system. This plugin uses
    the os_distro and os_version tags of an image and the name and version attributes of
    the OS parameter.

    If multiple images match, the most recent image is returned.

    :param provider: The provider to query for an image
    :param os: The operating system and version (using os_distro and os_version metadata)
    :param name: An optional string that the image name should contain
    """
    global FIND_IMAGE_RESULT

    ident = (provider.name, os.name.lower(), str(os.version).lower(), name)
    if ident in FIND_IMAGE_RESULT:
        return FIND_IMAGE_RESULT[ident]

    sess = None
    try:
        global IMAGES
        if provider.name not in IMAGES:
            auth = v3.Password(
                auth_url=provider.connection_url,
                username=provider.username,
                password=provider.password,
                project_name=provider.tenant,
                user_domain_id="default",
                project_domain_id="default",
            )
            sess = session.Session(auth=auth, verify=provider.verify_cert)
            client = glance_client.Client("2", session=sess)

            IMAGES[provider.name] = list(client.images.list())

        selected = (datetime.datetime(1900, 1, 1), None)
        for image in IMAGES[provider.name]:
            # only images that are public
            if (
                ("image_location" not in image and image["visibility"] == "public")
                and ("os_distro" in image and "os_version" in image)
                and (
                    image["os_distro"].lower() == os.name.lower()
                    and image["os_version"].lower() == str(os.version).lower()
                )
                and (name is None or name in image["name"])
            ):
                t = datetime.datetime.strptime(
                    image["updated_at"], "%Y-%m-%dT%H:%M:%SZ"
                )
                if t > selected[0]:
                    selected = (t, image)

        if selected[1] is None:
            raise Exception(
                "No image found for os %s and version %s" % (os.name, os.version)
            )

        result = selected[1]["id"]
        FIND_IMAGE_RESULT[ident] = result
        return result
    except keystoneauth1.exceptions.http.Unauthorized:
        # Make sure that the model compiles when the tenant has not been created yet
        return Unknown(None)
    except keystoneauth1.exceptions.connection.ConnectFailure:
        # Make sure that the model compiles when the openstack instance is down
        return Unknown(None)
    finally:
        if sess is not None:
            sess.session.close()


FLAVORS = {}
FIND_FLAVOR_RESULT = {}


@plugin
def find_flavor(
    provider: "openstack::Provider",
    vcpus: "number",
    ram: "number",
    pinned: "bool" = False,
) -> "string":
    """
    Find the flavor that matches the closest to the resources requested.

    :param vcpus: The number of virtual cpus in the flavor
    :param ram: The amount of ram in gigabyte
    :param pinned: Wether the CPUs need to be pinned (#vcpu == #pcpu)
    """
    global FLAVORS
    global FIND_FLAVOR_RESULT

    ident = (provider.name, vcpus, ram, pinned)
    if ident in FIND_FLAVOR_RESULT:
        return FIND_FLAVOR_RESULT[ident]

    sess = None
    try:
        if provider.name not in FLAVORS:
            auth = v3.Password(
                auth_url=provider.connection_url,
                username=provider.username,
                password=provider.password,
                project_name=provider.tenant,
                user_domain_id="default",
                project_domain_id="default",
            )
            sess = session.Session(auth=auth, verify=provider.verify_cert)
            client = nova_client.Client("2.1", session=sess)

            FLAVORS[provider.name] = list(client.flavors.list())

        selected: Tuple[int, Optional[flavors.Flavor]] = (1000000, None)
        for flavor in FLAVORS[provider.name]:
            keys = flavor.get_keys()
            is_pinned = "hw:cpu_policy" in keys and keys["hw:cpu_policy"] == "dedicated"
            if is_pinned ^ pinned:
                continue

            d_cpu = flavor.vcpus - vcpus
            d_ram = (flavor.ram / 1024) - ram
            distance = math.sqrt(math.pow(d_cpu, 2) + math.pow(d_ram, 2))
            if d_cpu >= 0 and d_ram >= 0 and distance < selected[0]:
                selected = (distance, flavor)

        if selected[1] is None:
            raise PluginException(
                "Couldn't find a flavor with at least %s %s CPUs and %s Gigabytes of RAM."
                % (vcpus, "pinned" if pinned else "unpinned", ram)
            )

        FIND_FLAVOR_RESULT[ident] = selected[1].name
        return selected[1].name
    except keystoneauth1.exceptions.http.Unauthorized:
        # Make sure that the model compiles when the tenant has not been created yet
        return Unknown(None)
    except keystoneauth1.exceptions.connection.ConnectFailure:
        # Make sure that the model compiles when the openstack instance is down
        return Unknown(None)
    finally:
        if sess is not None:
            sess.session.close()


class OpenstackAdminResource(PurgeableResource, ManagedResource):
    fields = ("admin_user", "admin_password", "admin_tenant", "auth_url", "verify_cert")

    @staticmethod
    def get_admin_user(exporter, resource):
        return resource.provider.username

    @staticmethod
    def get_admin_password(exporter, resource):
        return resource.provider.password

    @staticmethod
    def get_admin_tenant(exporter, resource):
        return resource.provider.tenant

    @staticmethod
    def get_auth_url(exporter, resource):
        return resource.provider.connection_url

    @staticmethod
    def get_verify_cert(exporter, resource):
        return resource.provider.verify_cert


class OpenstackResource(OpenstackAdminResource):
    fields = ("project",)

    @staticmethod
    def get_project(exporter, resource):
        return resource.project.name


@resource("openstack::Flavor", agent="provider.name", id_attribute="name")
class Flavor(OpenstackAdminResource):
    """
    A flavor is an available hardware configuration for a server.
    """

    fields = (
        "name",
        "ram",
        "vcpus",
        "disk",
        "flavor_id",
        "ephemeral",
        "swap",
        "rxtx_factor",
        "is_public",
        "extra_specs",
    )

    @staticmethod
    def get_extra_specs(_, obj):
        return {key: str(val) for key, val in obj.extra_specs.items()}


@resource("openstack::Image", agent="provider.name", id_attribute="name")
class Image(OpenstackAdminResource):
    fields = (
        "name",
        "uri",
        "container_format",
        "disk_format",
        "image_id",
        "visibility",
        "protected",
        "metadata",
        "skip_on_deploy",
        "purge_on_delete",
    )


@resource("openstack::VirtualMachine", agent="provider.name", id_attribute="name")
class VirtualMachine(OpenstackResource):
    """
    A virtual machine managed by a hypervisor or IaaS
    """

    fields = (
        "name",
        "flavor",
        "image",
        "key_name",
        "user_data",
        "key_value",
        "ports",
        "security_groups",
        "config_drive",
        "metadata",
        "personality",
    )

    @staticmethod
    def get_key_name(exporter, vm):
        return vm.key_pair.name

    @staticmethod
    def get_key_value(exporter, vm):
        return vm.key_pair.public_key

    @staticmethod
    def get_user_data(exporter, vm):
        """
        Return an empty string when the user_data value is unknown
        TODO: this is a hack
        """
        try:
            ua = vm.user_data
        except proxy.UnknownException:
            ua = ""
        return ua

    @staticmethod
    def get_ports(_, vm):
        ports = []
        for p in vm.ports:
            port = {
                "name": p.name,
                "address": None,
                "network": p.subnet.name,
                "dhcp": p.dhcp,
                "index": p.port_index,
            }
            try:
                port["address"] = p.address
            except proxy.UnknownException:
                pass
            ports.append(port)

        return ports

    @staticmethod
    def get_security_groups(_, vm):
        return sorted([v.name for v in vm.security_groups])


@resource("openstack::Network", agent="provider.name", id_attribute="name")
class Network(OpenstackResource):
    """
    This class represents a network in neutron
    """

    fields = (
        "name",
        "external",
        "physical_network",
        "network_type",
        "segmentation_id",
        "shared",
        "vlan_transparent",
    )


@resource("openstack::Subnet", agent="provider.name", id_attribute="name")
class Subnet(OpenstackResource):
    """
    This class represent a subnet in neutron
    """

    fields = (
        "name",
        "network_address",
        "dhcp",
        "allocation_start",
        "allocation_end",
        "network",
        "dns_servers",
        "gateway_ip",
        "disable_gateway_ip",
    )

    @staticmethod
    def get_network(_, subnet):
        return subnet.network.name

    @staticmethod
    def get_gateway_ip(_, subnet):
        try:
            return subnet.gateway_ip
        except ast.OptionalValueException:
            return None


@resource("openstack::Router", agent="provider.name", id_attribute="name")
class Router(OpenstackResource):
    """
    This class represent a router in neutron
    """

    fields = ("name", "subnets", "gateway", "ports", "routes")

    @staticmethod
    def get_gateway(_, router):
        if hasattr(router.ext_gateway, "name"):
            return router.ext_gateway.name

        return ""

    @staticmethod
    def get_routes(_, router):
        routes = {}
        for route in router.routes:
            try:
                routes[route.destination] = route.nexthop
            except proxy.UnknownException:
                pass
        return routes

    @staticmethod
    def get_subnets(_, router):
        return sorted([subnet.name for subnet in router.subnets])

    @staticmethod
    def get_ports(_, router):
        return [p.name for p in router.ports]


class Port(OpenstackResource):
    """
    A generic port
    """

    fields = ("name", "address", "subnet", "network")

    @staticmethod
    def get_address(exporter, port):
        try:
            return port.address
        except proxy.UnknownException:
            return ""

    @staticmethod
    def get_subnet(_, port):
        return port.subnet.name

    @staticmethod
    def get_network(_, port):
        return port.subnet.network.name


@resource("openstack::RouterPort", agent="provider.name", id_attribute="name")
class RouterPort(Port):
    """
    A port in a router
    """

    fields = ("name", "address", "subnet", "router", "network")

    @staticmethod
    def get_router(_, port):
        return port.router.name


@resource("openstack::HostPort", agent="provider.name", id_attribute="name")
class HostPort(Port):
    """
    A port in a router
    """

    fields = (
        "host",
        "portsecurity",
        "dhcp",
        "port_index",
        "retries",
        "wait",
        "allowed_address_pairs",
        "wait_for_vm",
    )

    @staticmethod
    def get_host(_, port):
        return port.vm.name

    @staticmethod
    def get_allowed_address_pairs(_, port):
        pairs = {}
        for pair in port.allowed_address_pairs:
            try:
                pairs[pair.address] = pair.mac
            except ast.OptionalValueException:
                pairs[pair.address] = None

        return pairs

    @staticmethod
    def get_wait_for_vm(_, port):
        """field used to determine if we expect the VM to be present at all"""
        return not (port.vm.purged)


@resource("openstack::SecurityGroup", agent="provider.name", id_attribute="name")
class SecurityGroup(OpenstackResource):
    """
    A security group in an OpenStack tenant
    """

    fields = ("name", "description", "manage_all", "rules", "retries", "wait")

    @staticmethod
    def get_rules(exporter, group):
        rules = []
        dedup = set()
        for rule in group.rules:
            json_rule = {"protocol": rule.ip_protocol, "direction": rule.direction}

            if rule.port > 0:
                json_rule["port_range_min"] = rule.port
                json_rule["port_range_max"] = rule.port

            else:
                json_rule["port_range_min"] = rule.port_min
                json_rule["port_range_max"] = rule.port_max

            if json_rule["port_range_min"] == 0:
                json_rule["port_range_min"] = None

            if json_rule["port_range_max"] == 0:
                json_rule["port_range_max"] = None

            try:
                json_rule["remote_ip_prefix"] = rule.remote_prefix
            except Exception:
                pass

            try:
                json_rule["remote_group"] = rule.remote_group.name
            except Exception:
                pass

            key = tuple(sorted(json_rule.items()))
            if key not in dedup:
                dedup.add(key)
                rules.append(json_rule)
            else:
                LOGGER.warning(
                    "A duplicate rule exists in security group %s", group.name
                )

        return rules


@resource("openstack::FloatingIP", agent="provider.name", id_attribute="name")
class FloatingIP(OpenstackResource):
    """
    A floating ip
    """

    fields = ("name", "port", "external_network", "address")

    @staticmethod
    def get_port(_, fip):
        return fip.port.name

    @staticmethod
    def get_external_network(_, fip):
        return fip.external_network.name

    @staticmethod
    def get_address(_, fip):
        if fip.force_ip:
            return fip.address
        return None


class KeystoneResource(PurgeableResource, ManagedResource):
    fields = (
        "admin_token",
        "url",
        "admin_user",
        "admin_password",
        "admin_tenant",
        "auth_url",
        "verify_cert",
    )

    @staticmethod
    def get_admin_token(_, resource):
        return resource.provider.token

    @staticmethod
    def get_url(_, resource):
        return os.path.join(resource.provider.admin_url, "v2.0/")

    @staticmethod
    def get_admin_user(exporter, resource):
        return resource.provider.username

    @staticmethod
    def get_admin_password(exporter, resource):
        return resource.provider.password

    @staticmethod
    def get_admin_tenant(exporter, resource):
        return resource.provider.tenant

    @staticmethod
    def get_auth_url(exporter, resource):
        return resource.provider.connection_url

    @staticmethod
    def get_verify_cert(exporter, resource):
        return resource.provider.verify_cert


@resource("openstack::Project", agent="provider.name", id_attribute="name")
class Project(KeystoneResource):
    """
    This class represents a project in keystone
    """

    fields = ("name", "enabled", "description")

    @staticmethod
    def get_project(exporter, resource):
        return resource.project.name


@resource("openstack::User", agent="provider.name", id_attribute="name")
class User(KeystoneResource):
    """
    A user in keystone
    """

    fields = ("name", "email", "enabled", "password")


@resource("openstack::Role", agent="provider.name", id_attribute="role_id")
class Role(KeystoneResource):
    """
    A role that adds a user to a project
    """

    fields = ("role_id", "role", "project", "user", "project")

    @staticmethod
    def get_project(exporter, resource):
        return resource.project.name

    @staticmethod
    def get_user(exporter, resource):
        return resource.user.name


@resource("openstack::Service", agent="provider.name", id_attribute="name")
class Service(KeystoneResource):
    """
    A service for which endpoints can be registered
    """

    fields = ("name", "type", "description")


@resource("openstack::EndPoint", agent="provider.name", id_attribute="service_id")
class EndPoint(KeystoneResource):
    """
    An endpoint for a service
    """

    fields = ("region", "internal_url", "public_url", "admin_url", "service_id")


MANAGED_DEPENDENCIES = {
    "openstack::Project",
    "openstack::Network",
    "openstack::Router",
    "openstack::Subnet",
    "openstack::VirtualMachine",
    "openstack::HostPort",
    "openstack::FloatingIP",
    "openstack::SecurityGroup",
}


def resource_collector(resource_model):
    purged_resources = defaultdict(lambda: defaultdict(lambda: {}))
    non_purged_resources = defaultdict(lambda: defaultdict(lambda: {}))

    for current_resource in resource_model.values():
        rtype = current_resource.id.entity_type
        if rtype in MANAGED_DEPENDENCIES:
            resource_name = current_resource.name
            provider = current_resource.model.provider
            if not current_resource.purged:
                non_purged_resources[provider][rtype][resource_name] = current_resource
            else:
                purged_resources[provider][rtype][resource_name] = current_resource

    return purged_resources, non_purged_resources


@dependency_manager
def openstack_dependencies(config_model, resource_model):
    purged_resources, non_purged_resources = resource_collector(resource_model)
    for project, collector in non_purged_resources.items():
        set_dependencies_on_non_purged_resources(collector)
    for project, collector in purged_resources.items():
        set_dependencies_on_purged_resources(collector)


def set_dependencies_on_purged_resources(
    collector: Dict[str, OpenstackResource]
) -> None:
    """
    This method only sets the dependencies between a VM and its ports!
    """
    vms = collector.get("openstack::VirtualMachine", {})
    ports = collector.get("openstack::HostPort", {})

    # When the VM is purged, all its purged ports should be deployed first
    for vm in vms.values():
        for vm_port in vm.ports:
            if vm_port["name"] in ports:
                port_id = ports[vm_port["name"]].id
                vm.requires.add(port_id)


def set_dependencies_on_non_purged_resources(
    collector: Dict[str, OpenstackResource]
) -> None:
    projects = collector.get("openstack::Project", {})
    networks = collector.get("openstack::Network", {})
    routers = collector.get("openstack::Router", {})
    subnets = collector.get("openstack::Subnet", {})
    vms = collector.get("openstack::VirtualMachine", {})
    ports = collector.get("openstack::HostPort", {})
    fips = collector.get("openstack::FloatingIP", {})
    sgs = collector.get("openstack::SecurityGroup", {})
    router_map = {}

    # they require the tenant to exist
    for network in networks.values():
        if network.model.project.name in projects:
            network.requires.add(projects[network.model.project.name].id)

    for router in routers.values():
        if router.model.project.name in projects:
            router.requires.add(projects[router.model.project.name].id)

        # depend on the attached subnets
        for subnet_name in router.subnets:
            if subnet_name in subnets:
                router.requires.add(subnets[subnet_name].id)

            # create external/subnet mapping
            router_map[(router.gateway, subnet_name)] = router

        if router.gateway in networks:
            router.requires.add(networks[router.gateway].id)

    for subnet in subnets.values():
        if subnet.model.project.name in projects:
            subnet.requires.add(projects[subnet.model.project.name].id)

        # also require the network it is attached to
        if subnet.model.network.name in networks:
            subnet.requires.add(networks[subnet.model.network.name].id)

    for vm in vms.values():
        if vm.model.project.name in projects:
            vm.requires.add(projects[vm.model.project.name].id)

        for port in vm.ports:
            if port["network"] in subnets:
                vm.requires.add(subnets[port["network"]].id)

        for sg in vm.security_groups:
            if sg in sgs:
                vm.requires.add(sgs[sg].id)

    for port in ports.values():
        if port.model.project.name in projects:
            port.requires.add(projects[port.model.project.name].id)

        if port.network in projects:
            port.requires.add(subnets[port.network].id)

        if port.host in vms:
            port.requires.add(vms[port.host].id)

    for fip in fips.values():
        if fip.external_network in networks:
            fip.requires.add(networks[fip.external_network].id)

        if fip.port in ports:
            port = ports[fip.port]
            fip.requires.add(port.id)

            # find router on which this floating ip is added
            key = (fip.external_network, port.subnet)
            if key in router_map:
                fip.requires.add(router_map[key].id)


CRED_TIMEOUT = 600
RESOURCE_TIMEOUT = 10


class OpenStackHandler(CRUDHandler):
    @cache(timeout=CRED_TIMEOUT)
    def get_session(self, auth_url, project, admin_user, admin_password, verify_cert):
        auth = v3.Password(
            auth_url=auth_url,
            username=admin_user,
            password=admin_password,
            project_name=project,
            user_domain_id="default",
            project_domain_id="default",
        )
        sess = session.Session(auth=auth, verify=verify_cert)
        return sess

    @cache(timeout=CRED_TIMEOUT)
    def get_nova_client(
        self, auth_url, project, admin_user, admin_password, verify_cert
    ):
        return nova_client.Client(
            "2.1",
            session=self.get_session(
                auth_url, project, admin_user, admin_password, verify_cert
            ),
        )

    @cache(timeout=CRED_TIMEOUT)
    def get_neutron_client(
        self, auth_url, project, admin_user, admin_password, verify_cert
    ):
        return neutron_client.Client(
            "2.0",
            session=self.get_session(
                auth_url, project, admin_user, admin_password, verify_cert
            ),
        )

    @cache(timeout=CRED_TIMEOUT)
    def get_keystone_client(
        self, auth_url, project, admin_user, admin_password, verify_cert
    ):
        return keystone_client.Client(
            session=self.get_session(
                auth_url, project, admin_user, admin_password, verify_cert
            )
        )

    @cache(timeout=CRED_TIMEOUT)
    def get_glance_client(
        self, auth_url, project, admin_user, admin_password, verify_cert
    ):
        return glance_client.Client(
            "2",
            session=self.get_session(
                auth_url, project, admin_user, admin_password, verify_cert
            ),
        )

    def pre(self, ctx, resource):
        project = resource.admin_tenant
        self._nova = self.get_nova_client(
            resource.auth_url,
            project,
            resource.admin_user,
            resource.admin_password,
            resource.verify_cert,
        )
        self._neutron = self.get_neutron_client(
            resource.auth_url,
            project,
            resource.admin_user,
            resource.admin_password,
            resource.verify_cert,
        )
        self._keystone = self.get_keystone_client(
            resource.auth_url,
            project,
            resource.admin_user,
            resource.admin_password,
            resource.verify_cert,
        )
        self._glance = self.get_glance_client(
            resource.auth_url,
            project,
            resource.admin_user,
            resource.admin_password,
            resource.verify_cert,
        )

    def post(self, ctx, resource):
        self._nova = None
        self._neutron = None
        self._keystone = None
        self._glance = None

    def get_project_id(self, resource, name):
        """
        Retrieve the id of a project based on the given name
        """
        # Fallback for non admin users
        if resource.admin_tenant == name:
            session = self.get_session(
                resource.auth_url,
                resource.project,
                resource.admin_user,
                resource.admin_password,
                resource.verify_cert,
            )
            return session.get_project_id()

        try:
            project = self._keystone.projects.find(name=name)
            return project.id
        except Exception:
            raise

    def get_network(self, project_id, name=None, network_id=None):
        """
        Retrieve the network id based on the name of the network
        """
        query = {}
        if project_id is not None and network_id is None:
            query["tenant_id"] = project_id

        if name is not None:
            query["name"] = name
        elif network_id is not None:
            query["id"] = network_id
        else:
            raise Exception("Either a name or an id needs to be provided.")

        networks = self._neutron.list_networks(**query)
        if len(networks["networks"]) == 0:
            return None

        elif len(networks["networks"]) > 1:
            raise Exception(
                "Found more than one network with name %s/id %s for project %s"
                % (name, network_id, project_id)
            )

        else:
            return networks["networks"][0]

    def get_subnet(self, project_id, name=None, subnet_id=None):
        """
        Retrieve the subnet id based on the name of the network
        """
        if name is not None:
            subnets = self._neutron.list_subnets(tenant_id=project_id, name=name)
        elif subnet_id is not None:
            if project_id is not None:
                subnets = self._neutron.list_subnets(tenant_id=project_id, id=subnet_id)
            else:
                subnets = self._neutron.list_subnets(id=subnet_id)
        else:
            raise Exception("Either a name or an id needs to be provided.")

        if len(subnets["subnets"]) == 0:
            return None

        elif len(subnets["subnets"]) > 1:
            raise Exception(
                "Found more than one subnet with name %s for project %s"
                % (name, project_id)
            )

        else:
            return subnets["subnets"][0]

    def get_router(self, project_id=None, name=None, router_id=None):
        """
        [{
            'allowed_address_pairs': [],
            'extra_dhcp_opts': [],
            'updated_at': '2018-01-22T13:29:25Z',
            'device_owner': 'compute:nova',
            'revision_number': 8,
            'port_security_enabled': True,
            'binding:profile': {},
            'fixed_ips': [{'subnet_id': 'aad30b7b-ab7b-441b-843f-8cef149ef4a1', 'ip_address': '10.255.255.10'}],
            'id': 'd36a6022-652f-4d95-bae4-7301fb6a2b32',
            'security_groups': ['0625ff63-dbca-4078-ad50-ba2bce935c64'],
            'binding:vif_details': {'port_filter': True},
            'binding:vif_type': 'bridge',
            'mac_address': 'fa:16:3e:f3:e7:2b',
            'project_id': '727f8247b37f4199884676d19fef05cc',
            'status': 'ACTIVE',
            'binding:host_id': 'node1.inmanta.com',
            'description': '',
            'tags': [],
            'device_id': 'fd290dc1-962c-4b12-9994-09f08aa76fa1',
            'name': 'inmanta_unit_test_port',
            'admin_state_up': True,
            'network_id': '5dedda95-82d4-4a3a-9b8f-fa9a9c9e1997',
            'tenant_id': '727f8247b37f4199884676d19fef05cc',
            'created_at': '2018-01-22T13:29:21Z',
            'binding:vnic_type': 'normal'
        }]

            Retrieve the router id based on the name of the network
        """
        query = {}
        if project_id is not None:
            query["tenant_id"] = project_id

        if name is not None:
            query["name"] = name
        elif router_id is not None:
            query["id"] = router_id
        else:
            raise Exception("Either a name or an id needs to be provided.")

        routers = self._neutron.list_routers(**query)

        if len(routers["routers"]) == 0:
            return None

        elif len(routers["routers"]) > 1:
            raise Exception(
                "Found more than one router with name %s for project %s"
                % (name, project_id)
            )

        else:
            return routers["routers"][0]

    def get_host_id(self, project_id, name):
        return self.get_host(project_id, name).id

    def get_host(self, project_id, name):
        """
        Retrieve the router id based on the name of the network
        """
        vms = self._nova.servers.findall(name=name)

        if len(vms) == 0:
            return None

        elif len(vms) > 1:
            raise Exception(
                "Found more than one VM with name %s for project %s"
                % (name, project_id)
            )

        else:
            return vms[0]

    def get_host_for_id(self, server_id):
        """
        Retrieve the router id based on the name of the network
        """
        vms = self._nova.servers.findall(id=server_id)

        if len(vms) == 0:
            return None

        elif len(vms) > 1:
            raise Exception("Found more than one VM with id %s" % (server_id))

        else:
            return vms[0]

    def get_security_group(self, ctx, project_id, name=None, group_id=None):
        """
        Get security group details from openstack
        """
        if (name is None) == (group_id is None):
            raise Exception(
                "Argument 'name' or 'group_id' should be provided, but never both"
            )

        if name is not None:
            sgs = self._neutron.list_security_groups(project_id=project_id, name=name)
        elif group_id is not None:
            sgs = self._neutron.list_security_groups(project_id=project_id, id=group_id)

        if len(sgs["security_groups"]) == 0:
            return None
        elif len(sgs["security_groups"]) > 1:
            ctx.warning(
                "Multiple security groups with name %(name)s exist.",
                name=name,
                groups=sgs["security_groups"],
            )

        return sgs["security_groups"][0]


@provider("openstack::Flavor", name="openstack")
class FlavorHandler(OpenStackHandler):
    # NOTE: Description is mentioned in the documentation, but does not seem to work currently
    def read_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ):
        flavors = self._nova.flavors.list()
        matching_flavors = [
            flavor for flavor in flavors if resource.name == flavor.name
        ]
        if not matching_flavors:
            raise ResourcePurged()

        elif len(matching_flavors) > 1:
            raise Exception(f"More than one flavor with name {resource.name}")

        else:
            matching_flavor = matching_flavors[0]

            # If a flavor_id was manually set to anything else then null or auto,
            # and it is changed, an error will be thrown by update_resource.
            if not (resource.flavor_id == "auto" or not resource.flavor_id):
                resource.flavor_id = matching_flavor.id

            ctx.set("flavor_id", matching_flavor.id)

            resource.purged = False
            resource.ram = matching_flavor.ram
            resource.vcpus = matching_flavor.vcpus
            resource.disk = matching_flavor.disk
            resource.ephemeral = matching_flavor.ephemeral

            if matching_flavor.swap:
                resource.swap = matching_flavor.swap
            else:
                resource.swap = 0

            resource.rxtx_factor = matching_flavor.rxtx_factor
            resource.is_public = matching_flavor.is_public
            resource.extra_specs = matching_flavor.get_keys()

    def create_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ):
        flavor = self._nova.flavors.create(
            resource.name,
            resource.ram,
            resource.vcpus,
            resource.disk,
            resource.flavor_id,
            resource.ephemeral,
            resource.swap,
            resource.rxtx_factor,
            resource.is_public,
        )
        if resource.extra_specs:
            flavor.set_keys(resource.extra_specs)

        ctx.set_created()

    def delete_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ):
        self._nova.flavors.delete(ctx.get("flavor_id"))
        ctx.set_purged()

    def update_resource(
        self,
        ctx: handler.HandlerContext,
        changes: dict,
        resource: resources.PurgeableResource,
    ):
        illegal_args = [arg for arg in changes if arg not in ("extra_specs")]
        if illegal_args:
            raise InvalidOperation(
                f"Updating properties {illegal_args} for Flavor is not supported"
            )

        flavor = self._nova.flavors.get(ctx.get("flavor_id"))
        if changes.get("extra_specs"):
            new_extra_specs = changes["extra_specs"]["desired"]
            current_extra_specs = flavor.get_keys()
            unset_keys = [
                spec for spec in current_extra_specs if spec not in new_extra_specs
            ]

            flavor.unset_keys(unset_keys)
            flavor.set_keys(new_extra_specs)
        ctx.set_updated()


@provider("openstack::Image", name="openstack")
class ImageHandler(OpenStackHandler):
    def _get_image(self, resource: resources.PurgeableResource):
        if resource.image_id:
            return self._get_image_by_id(resource.image_id)
        else:
            matching_images = [
                image
                for image in self._glance.images.list()
                if resource.name == image.name
            ]
            if not matching_images:
                return None
            elif len(matching_images) > 1:
                raise Exception(f"More than one image with name {resource.name}")
            else:
                return matching_images[0]

    def _get_image_by_id(self, image_id: "std::uuid"):
        """
        Return the image with the given ID or None if no such image was found.
        """
        try:
            return self._glance.images.get(image_id)
        except glance_exceptions.HTTPNotFound:
            return None

    # keep track of which keys we had set before
    # so we can reconstruct the metadata dictionary correctly
    def _get_inmanta_metadata(self, image):
        try:
            inmanta_managed_keys = image.inmanta_managed_keys.split(",")
        except AttributeError:
            return {}

        metadata_dict = {}
        for key in inmanta_managed_keys:
            metadata_dict[key] = image.get(key)

        return metadata_dict

    def read_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ):
        image = self._get_image(resource)

        # check for changes
        if not image:
            raise ResourcePurged()
        else:
            ctx.set("image_id", image.id)

            resource.purged = False

            # Id is always the same, but name could technically change if the id is set.
            resource.name = image.name
            resource.image_id = image.id

            # uri is not an official openstack attribute
            try:
                resource.uri = image.uri
            except AttributeError:
                ctx.warning(
                    f"Could not validate uri attribute for image {resource.name}: attribute missing from OpenStack object."
                )

            resource.container_format = image.container_format
            resource.disk_format = image.disk_format
            resource.visibility = image.visibility
            resource.protected = image.protected
            resource.metadata = self._get_inmanta_metadata(image)
            # resource.skip_on_deploy doesn't matter for existing resources

    def create_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ):
        # glance.images.create takes only kwargs.
        # To set something to None, the key has to be missing.
        # Setting id to None for example generates an error.
        kwargs = {
            "name": resource.name,
            "uri": resource.uri,
            "container_format": resource.container_format,
            "disk_format": resource.disk_format,
            "visibility": resource.visibility,
            "protected": resource.protected,
        }
        if resource.image_id:
            kwargs["id"] = resource.image_id

        inmanta_managed_keys = []
        for key, value in resource.metadata.items():
            inmanta_managed_keys.append(key)
            kwargs[key] = value

        kwargs["inmanta_managed_keys"] = ",".join(inmanta_managed_keys)

        image = self._glance.images.create(**kwargs)
        self._glance.images.image_import(
            image.id, method="web-download", uri=resource.uri
        )
        if resource.skip_on_deploy:
            raise SkipResource(
                f"Started deployment of image {resource.name}"
                ", but not waiting for it to deploy, because skip_on_deploy is set"
            )
        else:
            self._wait_for_image_to_become_active(image.id)
        ctx.set_created()

    def _wait_for_image_to_become_active(
        self, image_id: "std::uuid", timeout: int = 60
    ) -> None:
        """
        Wait until the image with the given ID enters the `active` status.

        :param timeout: An exception is raised when the image doesn't enter the `active` state
                        after this amount of seconds.
        """
        if timeout < 0:
            raise ValueError(f"Timeout cannot be negative: {timeout}")
        start_time = time.time()
        image = None
        while time.time() < start_time + timeout:
            image = self._get_image_by_id(image_id)
            if image and image.status == "active":
                return
            time.sleep(0.1)
        raise Exception(
            f"A timeout occurred while waiting for image {image_id} to enter the `active` state "
            f"(status={image.status if image else None})"
        )

    def delete_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ):
        self._glance.images.delete(ctx.get("image_id"))

        ctx.set_purged()

    def update_resource(
        self,
        ctx: handler.HandlerContext,
        changes: dict,
        resource: resources.PurgeableResource,
    ):
        # other parameters should never be updated
        legal_args = (
            "visibility",
            "protected",
            "metadata",
            "skip_on_deploy",
            "purge_on_delete",
        )
        illegal_args = [arg for arg in changes if arg not in legal_args]

        if illegal_args:
            raise InvalidOperation(
                f"Updating properties {illegal_args} for Image is not supported"
            )

        kwargs = {}
        # Properties that are no longer used are not set to none,
        # instead they are passed as a list
        remove_props = []
        inmanta_managed_keys = ""
        for key in changes:
            if key == "visibility":
                kwargs["visibility"] = changes.get(key)["desired"]
            elif key == "protected":
                kwargs["protected"] = changes.get(key)["desired"]
            elif key == "metadata":
                current = changes.get(key)["current"]
                desired = changes.get(key)["desired"]

                for key in current:
                    if key not in desired:
                        remove_props.append(key)

                for key, value in desired.items():
                    kwargs[key] = value

                inmanta_managed_keys = ",".join(desired.keys())

        if inmanta_managed_keys:
            kwargs["inmanta_managed_keys"] = inmanta_managed_keys

        if remove_props:
            kwargs["remove_props"] = remove_props

        self._glance.images.update(ctx.get("image_id"), **kwargs)
        ctx.set_updated()


@provider("openstack::VirtualMachine", name="openstack")
class VirtualMachineHandler(OpenStackHandler):
    @cache(timeout=1, cache_none=False)
    def get_vm(self, ctx, resource):
        if resource.project == resource.admin_tenant:
            servers = self._nova.servers.list(search_opts={"name": resource.name})
        else:
            try:
                project_id = self.get_project_id(resource, resource.project)
                servers = self._nova.servers.list(
                    search_opts={
                        "all_tenants": True,
                        "tenant_id": project_id,
                        "name": resource.name,
                    }
                )
            except Exception:
                ctx.exception(
                    "Unable to retrieve server list with a scoped login on project %(admin_project)s, "
                    "for project %(project)s. This only works with admin credentials.",
                    admin_project=resource.admin_tenant,
                    project=resource.project,
                    traceback=traceback.format_exc(),
                )
                return None

        # OS query semantic are not == but "in". So "mon" matches mon and mongo
        # Filter again to ensure a correct result
        servers = [x for x in servers if x.name == resource.name]
        if len(servers) == 0:
            return None

        elif len(servers) == 1:
            return servers[0]

        else:
            raise Exception(
                "Multiple virtual machines with name %s exist." % resource.name
            )

    @cache(timeout=10, cache_none=False)
    def _port_id(self, port_name):
        ports = self._neutron.list_ports(name=port_name)
        if len(ports["ports"]) > 0:
            return ports["ports"][0]["id"]

        return None

    @cache(timeout=10, cache_none=False)
    def _get_subnet_id(self, subnet_name):
        subnets = self._neutron.list_subnets(name=subnet_name)
        if len(subnets["subnets"]) > 0:
            return subnets["subnets"][0]["network_id"]

        return None

    def _create_nic_config(self, port):
        nic = {}
        port_id = self._port_id(port["name"])
        if port_id is None:
            network = self._get_subnet_id(port["network"])
            if network is None:
                raise SkipResource("Network %s not found" % port["network"])
            nic["net-id"] = network
            if port["address"] is not None:
                nic["v4-fixed-ip"] = port["address"]
        else:
            nic["port-id"] = port_id

        return nic

    def _build_nic_list(self, ports):
        # build a list of nics for this server based on the index in the ports
        no_sort = sorted(
            [p for p in ports if p["index"] == 0], key=lambda x: x["network"]
        )
        sort = sorted([p for p in ports if p["index"] > 0], key=lambda x: x["index"])

        return [self._create_nic_config(p) for p in sort] + [
            self._create_nic_config(p) for p in no_sort
        ]

    def _build_sg_list(self, ctx, resource: resources.PurgeableResource):
        sg_list = []
        for group in resource.security_groups:
            project_id = self.get_project_id(resource, resource.project)
            sg = self.get_security_group(ctx, project_id=project_id, name=group)
            if sg is not None:
                sg_list.append(sg["name"])
        return sg_list

    def _ensure_key(self, ctx, resource):
        keys = {k.name: k for k in self._nova.keypairs.list()}
        if resource.key_name not in keys:
            self._nova.keypairs.create(resource.key_name, resource.key_value)
            ctx.info("Created a new keypair with name %(name)s", name=resource.key_name)

    def read_resource(self, ctx, resource):
        """
        This method will check what the status of the give resource is on
        openstack.
        """
        server = self.get_vm(ctx, resource)
        if server is None:
            raise ResourcePurged()

        else:
            resource.purged = False
            resource.security_groups = [sg.name for sg in server.list_security_group()]
            # The port handler has to handle all network/port related changes

        ctx.set("server", server)

    def create_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        if resource.admin_tenant != resource.project:
            ctx.error(
                "The nova API does not allow to create virtual machines in an other project than the one logged into."
                " Current login %(admin_project)s, requested project %(project)s",
                admin_project=resource.admin_tenant,
                project=resource.project,
            )
            raise Exception()

        self._ensure_key(ctx, resource)
        flavor = self._nova.flavors.find(name=resource.flavor)
        nics = self._build_nic_list(resource.ports)
        args = dict(
            flavor=flavor.id,
            userdata=resource.user_data,
            nics=nics,
            security_groups=self._build_sg_list(ctx, resource),
            image=resource.image,
            key_name=resource.key_name,
            config_drive=resource.config_drive,
            meta=resource.metadata,
            files=resource.personality,
        )
        ctx.info(
            "Creating server with name %(name)s and options",
            name=resource.name,
            options=args,
        )
        self._nova.servers.create(resource.name, **args)
        ctx.set_created()

    def delete_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        server = ctx.get("server")
        server.delete()

        def is_server_deletion_finished() -> bool:
            ports = self._neutron.list_ports(device_id=server.id)
            if len(ports["ports"]) > 0:
                return False
            return self.get_vm(ctx, resource) is None

        # Wait until the server has been deleted
        count = 0
        ctx.info("Waiting until server is deleted.")
        while not is_server_deletion_finished() and count < 60:
            time.sleep(1)
            count += 1

        if count >= 60:
            ctx.warning("Delete still in progress, giving up waiting.")

        ctx.set_purged()

    def update_resource(
        self, ctx, changes: dict, resource: resources.PurgeableResource
    ) -> None:
        server = ctx.get("server")

        self._ensure_key(ctx, resource)
        if "security_groups" in changes:
            current = set(changes["security_groups"]["current"])
            desired = set(changes["security_groups"]["desired"])

            for new_rule in desired - current:
                self._nova.servers.add_security_group(server, new_rule)

            for remove_rule in current - desired:
                self._nova.servers.remove_security_group(server, remove_rule)

        ctx.set_updated()

    def facts(self, ctx, resource):
        ctx.debug("Finding facts for %s" % resource.id.resource_str())

        try:
            vm = self.get_vm(ctx, resource)

            networks = vm.networks

            facts = {}
            for name, ips in networks.items():
                for i in range(len(ips)):
                    facts["subnet_%s_ip_%d" % (name, i)] = ips[i]
                    if i == 0:
                        facts["subnet_%s_ip" % name] = ips[i]

            # Get the private ip of the first port
            project_id = self.get_project_id(resource, resource.project)
            network_one = None
            for port in resource.ports:
                if port["index"] == 1:
                    network_one = port["network"]

            if project_id is not None and network_one is not None:
                ports = self._neutron.list_ports(device_id=vm.id)
                for port in ports["ports"]:
                    for ips in port["fixed_ips"]:
                        subnet = self.get_subnet(project_id, subnet_id=ips["subnet_id"])
                        if subnet["name"] == network_one:
                            facts["ip_address"] = ips["ip_address"]

            return facts
        except Exception:
            return {}


@provider("openstack::Network", name="openstack")
class NetworkHandler(OpenStackHandler):
    def read_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ):
        network = self.facts(ctx, resource)

        if len(network) > 0:
            resource.purged = False
            resource.external = network["router:external"]
            if (
                "vlan_transparent" in network
                and network["vlan_transparent"] is not None
            ):
                resource.vlan_transparent = network["vlan_transparent"]

            if resource.physical_network != "":
                resource.physical_network = network["provider:physical_network"]

            if resource.network_type != "":
                resource.network_type = network["provider:network_type"]

            if resource.segmentation_id > 0:
                resource.segmentation_id = network["provider:segmentation_id"]

            ctx.set("network_id", network["id"])
            ctx.set("project_id", network["tenant_id"])

        else:
            raise ResourcePurged()

    def _create_dict(self, resource: Network, project_id):
        net = {
            "name": resource.name,
            "tenant_id": project_id,
            "admin_state_up": True,
            "router:external": resource.external,
            "shared": resource.shared,
        }

        if resource.physical_network != "":
            net["provider:physical_network"] = resource.physical_network

        if resource.network_type != "":
            net["provider:network_type"] = resource.network_type

        if resource.segmentation_id > 0:
            net["provider:segmentation_id"] = resource.segmentation_id

        if resource.vlan_transparent is not None:
            net["vlan_transparent"] = resource.vlan_transparent

        return net

    def create_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ):
        project_id = self.get_project_id(resource, resource.project)
        self._neutron.create_network(
            {"network": self._create_dict(resource, project_id)}
        )
        ctx.set_created()

    def delete_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ):
        network_id = ctx.get("network_id")
        self._neutron.delete_network(network_id)
        ctx.set_purged()

    def update_resource(
        self,
        ctx: handler.HandlerContext,
        changes: dict,
        resource: resources.PurgeableResource,
    ):
        network_id = ctx.get("network_id")
        self._neutron.update_network(
            network_id,
            {"network": {"name": resource.name, "router:external": resource.external}},
        )

        ctx.fields_updated(("name", "external"))
        ctx.set_updated()

    def facts(self, ctx, resource: Network):
        try:
            networks = self._neutron.list_networks(name=resource.name)["networks"]
        except NotFound:
            return {}

        if len(networks) == 0:
            return {}

        if len(networks) > 1:
            LOGGER.warning("Multiple networks with the same name available!")
            return {}

        return networks[0]


@provider("openstack::Router", name="openstack")
class RouterHandler(OpenStackHandler):
    def read_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        neutron_version = self.facts(ctx, resource)

        if len(neutron_version) > 0:
            ctx.set("neutron", neutron_version)
            resource.purged = False

        else:
            raise ResourcePurged()

        # get a list of all attached subnets
        ext_name = ""
        external_net_id = ""
        if (
            "external_gateway_info" in neutron_version
            and neutron_version["external_gateway_info"] is not None
        ):
            external_net_id = neutron_version["external_gateway_info"]["network_id"]

            networks = self._neutron.list_networks(id=external_net_id)
            if len(networks["networks"]) == 1:
                ext_name = networks["networks"][0]["name"]

        resource.gateway = ext_name

        ports = self._neutron.list_ports(device_id=neutron_version["id"])
        subnet_list = []
        for port in ports["ports"]:
            subnets = port["fixed_ips"]
            if port["name"] == "" or port["name"] not in resource.ports:
                for subnet in subnets:
                    try:
                        subnet_details = self._neutron.show_subnet(subnet["subnet_id"])[
                            "subnet"
                        ]
                        # skip external networks and neutron networks such as ha networks
                        if (
                            subnet_details["network_id"] != external_net_id
                            and subnet_details["tenant_id"] != ""
                        ):
                            subnet_list.append(subnet_details["name"])

                    except exceptions.NeutronClientException:
                        pass

        resource.subnets = sorted(subnet_list)

        routes = {}
        for route in neutron_version["routes"]:
            routes[route["destination"]] = route["nexthop"]

        resource.routes = routes

    def create_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource(
                "Cannot create network when project id is not yet known."
            )

        result = self._neutron.create_router(
            {"router": {"name": resource.name, "tenant_id": project_id}}
        )
        router_id = result["router"]["id"]
        ctx.info("Created router with id %(id)s", id=router_id)
        ctx.set_created()

        if len(resource.subnets) > 0:
            self._update_subnets(router_id, [], resource.subnets)
            ctx.info("Added subnets to router with id %(id)s", id=router_id)

        if resource.gateway is not None and resource.gateway != "":
            self._set_gateway(router_id, resource.gateway)
            ctx.info("Set gateway of router with id %(id)s", id=router_id)

    def delete_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        router_id = ctx.get("neutron")["id"]

        ports = self._neutron.list_ports(device_id=router_id)["ports"]
        for port in ports:
            if port["device_owner"] == "network:router_interface":
                ctx.info(
                    "Detach interface with port id %(port)s from router %(router_id)s",
                    port=port["id"],
                    router_id=router_id,
                )
                self._neutron.remove_interface_router(
                    router=router_id, body={"port_id": port["id"]}
                )

        self._neutron.delete_router(router_id)
        ctx.set_purged()

    def _update_subnets(self, router_id, current, desired):
        current = set(current)
        to = set(desired)

        # subnets to add to the router
        for subnet in to - current:
            # query for the subnet id
            subnet_data = self._neutron.list_subnets(name=subnet)
            if "subnets" not in subnet_data or len(subnet_data["subnets"]) != 1:
                raise Exception("Unable to find id of subnet %s" % subnet)

            subnet_id = subnet_data["subnets"][0]["id"]
            self._neutron.add_interface_router(
                router=router_id, body={"subnet_id": subnet_id}
            )

        # subnets to delete
        for subnet in current - to:
            # query for the subnet id
            subnet_data = self._neutron.list_subnets(name=subnet)
            if "subnets" not in subnet_data or len(subnet_data["subnets"]) != 1:
                raise Exception("Unable to find id of subnet %s" % subnet)

            subnet_id = subnet_data["subnets"][0]["id"]
            self._neutron.remove_interface_router(
                router=router_id, body={"subnet_id": subnet_id}
            )

    def _set_gateway(self, router_id, network):
        network = self.get_network(None, name=network)
        if network is None:
            raise Exception(
                "Unable to set router gateway because the gateway network that does not exist."
            )

        self._neutron.add_gateway_router(router_id, {"network_id": network["id"]})

    def update_resource(
        self,
        ctx: handler.HandlerContext,
        changes: dict,
        resource: resources.PurgeableResource,
    ) -> None:
        router_id = ctx.get("neutron")["id"]
        updated = False

        if "name" in changes:
            self._neutron.update_router(router_id, {"router": {"name": resource.name}})
            if not updated:
                ctx.set_updated()
                updated = True

        if "subnets" in changes:
            self._update_subnets(
                router_id, changes["subnets"]["current"], changes["subnets"]["desired"]
            )
            ctx.info("Modified subnets of router with id %(id)s", id=router_id)
            if not updated:
                ctx.set_updated()
                updated = True

        if "gateway" in changes:
            self._set_gateway(router_id, resource.gateway)
            ctx.info("Modified gateway of router with id %(id)s", id=router_id)
            if not updated:
                ctx.set_updated()
                updated = True

        if "routes" in changes:
            self._neutron.update_router(
                router_id,
                {
                    "router": {
                        "routes": [
                            {"nexthop": n, "destination": d}
                            for d, n in resource.routes.items()
                        ]
                    }
                },
            )
            if not updated:
                ctx.set_updated()
                updated = True

    def facts(self, ctx, resource: Router) -> dict:
        routers = self._neutron.list_routers(name=resource.name)

        if "routers" not in routers:
            return {}

        filtered_list = [rt for rt in routers["routers"] if rt["name"] == resource.name]

        if len(filtered_list) == 0:
            return {}

        if len(filtered_list) > 1:
            LOGGER.warning("Multiple routers with the same name available!")
            return {}

        router = filtered_list[0]
        return router


@provider("openstack::Subnet", name="openstack")
class SubnetHandler(OpenStackHandler):
    def read_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        neutron_version = self.facts(ctx, resource)

        if len(neutron_version) > 0:
            resource.purged = False
            resource.id = neutron_version["id"]
            resource.network_address = neutron_version["cidr"]
            resource.dhcp = neutron_version["enable_dhcp"]
            resource.network_id = neutron_version["network_id"]
            resource.dns_servers = neutron_version["dns_nameservers"]

            pool = neutron_version["allocation_pools"][0]
            if (
                resource.allocation_start != "" and resource.allocation_end != ""
            ):  # only change when they are both set
                resource.allocation_start = pool["start"]
                resource.allocation_end = pool["end"]

            resource.disable_gateway_ip = neutron_version["gateway_ip"] is None
            if not resource.disable_gateway_ip and resource.gateway_ip is not None:
                # A gateway_ip was set explicitly in the model
                resource.gateway_ip = neutron_version["gateway_ip"]

            ctx.set("neutron", neutron_version)
        else:
            raise ResourcePurged()

    def create_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource(
                "Cannot create network when project id is not yet known."
            )

        network = self.get_network(project_id, name=resource.network)
        if network is None:
            raise Exception(
                "Unable to create subnet because of network that does not exist."
            )

        body = {
            "name": resource.name,
            "network_id": network["id"],
            "enable_dhcp": resource.dhcp,
            "cidr": resource.network_address,
            "ip_version": 4,
            "tenant_id": project_id,
        }

        if len(resource.allocation_start) > 0 and len(resource.allocation_end) > 0:
            body["allocation_pools"] = [
                {"start": resource.allocation_start, "end": resource.allocation_end}
            ]

        if len(resource.dns_servers) > 0:
            body["dns_nameservers"] = resource.dns_servers

        if resource.disable_gateway_ip:
            body["gateway_ip"] = None
        elif resource.gateway_ip is not None:
            body["gateway_ip"] = resource.gateway_ip
        else:
            # Not adding the gateway_ip to the json body, will set
            # the gateway_ip to the first IP in the network.
            pass

        self._neutron.create_subnet({"subnet": body})
        ctx.set_created()

    def delete_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        neutron = ctx.get("neutron")
        self._neutron.delete_subnet(neutron["id"])
        ctx.set_purged()

    def update_resource(
        self,
        ctx: handler.HandlerContext,
        changes: dict,
        resource: resources.PurgeableResource,
    ) -> None:
        neutron = ctx.get("neutron")

        # Send everything that can be updated to the server, the API will figure out what to change
        body = {"subnet": {"enable_dhcp": resource.dhcp}}
        if len(resource.allocation_start) > 0 and len(resource.allocation_end) > 0:
            body["allocation_pools"] = [
                {"start": resource.allocation_start, "end": resource.allocation_end}
            ]

        if len(resource.dns_servers) > 0:
            body["dns_nameservers"] = resource.dns_servers

        if resource.disable_gateway_ip:
            body["gateway_ip"] = None
        else:
            body["gateway_ip"] = resource.gateway_ip

        self._neutron.update_subnet(neutron["id"], body)
        ctx.set_updated()

    @cache(timeout=5)
    def facts(self, ctx, resource):
        subnets = self._neutron.list_subnets(name=resource.name)

        if "subnets" not in subnets:
            return {}

        filtered_list = [sn for sn in subnets["subnets"] if sn["name"] == resource.name]

        if len(filtered_list) == 0:
            return {}

        if len(filtered_list) > 1:
            LOGGER.warning("Multiple subnets with the same name available!")
            return {}

        subnet = filtered_list[0]
        return subnet


@provider("openstack::RouterPort", name="openstack")
class RouterPortHandler(OpenStackHandler):
    def read_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource(
                "Cannot create network when project id is not yet known."
            )

        neutron_version = self.facts(ctx, resource)
        ctx.set("neutron", neutron_version)
        ctx.set("project_id", project_id)

        router = None
        if len(neutron_version) > 0:
            # Router stuff
            if neutron_version["device_id"] == "":
                resource.router = ""
            else:
                router = self.get_router(router_id=neutron_version["device_id"])
                resource.router = router["name"]

            # Network stuff
            network = self.get_network(
                project_id, network_id=neutron_version["network_id"]
            )
            resource.network = network["name"]
            ctx.set("network", network)

            # IP address / subnet stuff
            subnet = None
            if len(neutron_version["fixed_ips"]) > 1:
                raise Exception(
                    "This handler only supports ports that have an address in a single subnet."
                )
            elif len(neutron_version["fixed_ips"]) == 0:
                resource.subnet = ""
                resource.address = ""
            else:
                subnet = self.get_subnet(
                    project_id, subnet_id=neutron_version["fixed_ips"][0]["subnet_id"]
                )
                resource.subnet = subnet["name"]
                resource.address = neutron_version["fixed_ips"][0]["ip_address"]

            ctx.set("subnet", subnet)

            resource.purged = False
        else:
            raise ResourcePurged()

    def create_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        project_id = ctx.get("project_id")

        network = self.get_network(project_id, name=resource.network)
        if network is None:
            raise SkipResource(
                "Unable to create router port because the network does not exist."
            )

        subnet = self.get_subnet(project_id, name=resource.subnet)
        if subnet is None:
            raise SkipResource(
                "Unable to create router port because the subnet does not exist."
            )

        router = self.get_router(project_id, name=resource.router)
        if router is None:
            raise SkipResource(
                "Unable to create router port because the router does not exist."
            )

        body_value = {
            "port": {
                "admin_state_up": True,
                "name": resource.name,
                "network_id": network["id"],
            }
        }
        if resource.address != "":
            body_value["port"]["fixed_ips"] = [
                {"subnet_id": subnet["id"], "ip_address": resource.address}
            ]

        result = self._neutron.create_port(body=body_value)

        if "port" not in result:
            raise Exception("Unable to create port.")

        port_id = result["port"]["id"]

        # attach it to the router
        self._neutron.add_interface_router(router["id"], body={"port_id": port_id})
        ctx.set_created()

    def delete_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        port = ctx.get("neutron")

        if port["device_owner"] == "network:router_interface":
            ctx.info(
                "Detach interface with port id %(port)s from router %(router_id)s",
                port=port["id"],
                router_id=port["device_id"],
            )
            self._neutron.remove_interface_router(
                router=port["device_id"], body={"port_id": port["id"]}
            )
        else:
            self._neutron.delete_port(port["id"])

        ctx.set_purged()

    def update_resource(
        self,
        ctx: handler.HandlerContext,
        changes: dict,
        resource: resources.PurgeableResource,
    ) -> None:
        raise SkipResource("Making changes to router ports is not supported.")

    def facts(self, ctx, resource: RouterPort):
        ports = self._neutron.list_ports(name=resource.name)

        if "ports" not in ports:
            return {}

        filtered_list = [
            port for port in ports["ports"] if port["name"] == resource.name
        ]

        if len(filtered_list) == 0:
            return {}

        if len(filtered_list) > 1:
            LOGGER.warning("Multiple ports with the same name available!")
            return {}

        port = filtered_list[0]
        return port


@provider("openstack::HostPort", name="openstack")
class HostPortHandler(OpenStackHandler):
    def get_port(self, ctx, network_id, device_id):
        ports = self._neutron.list_ports(network_id=network_id, device_id=device_id)[
            "ports"
        ]
        ctx.debug(
            "Retrieved ports matching network %(network_id)s and device %(device_id)s",
            network_id=network_id,
            device_id=device_id,
            ports=ports,
        )
        if len(ports) > 0:
            return ports[0]
        return None

    def wait_for_active(self, ctx, project_id, resource):
        """
        A port cannot be attached to a VM when the VM is in the building state. This method waits a limited amount of
        time for the VM to become active. If it takes to long, this resource will be skipped.
        """
        tries = 0
        max_attempts = resource.retries if resource.retries > 0 else 1
        while tries < max_attempts:
            vm = self.get_host(project_id, resource.host)
            if vm is not None:
                vm_state = getattr(vm, "OS-EXT-STS:vm_state")
                if vm_state == "active":
                    return vm
                else:
                    ctx.info(
                        "VM for port is not in active state, but %(state)s. Waiting and retrying in 5 seconds.",
                        state=vm_state,
                    )
            else:
                if not resource.wait_for_vm:
                    # Vm doesn't exist, so we can assume this port doesn't exist either
                    # see https://github.com/inmanta/openstack/issues/286
                    raise ResourcePurged()
                ctx.info(
                    "VM for port doesn't exist. Waiting and retrying in 5 seconds."
                )

            tries += 1
            time.sleep(resource.wait)

        raise SkipResource(
            "Unable to create host port because vm is not in active state"
        )

    def read_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource(
                "Cannot create  a host port when project id is not yet known."
            )
        ctx.set("project_id", project_id)

        network = self.get_network(None, resource.network)
        if network is None:
            raise SkipResource(
                "Network %s for port %s not found." % (resource.network, resource.name)
            )
        ctx.set("network", network)

        vm = self.wait_for_active(ctx, project_id, resource)
        if vm is None:
            raise SkipResource(
                "Unable to create host port because the vm does not exist."
            )

        ctx.set("vm", vm)

        port = self.get_port(ctx, network["id"], vm.id)
        ctx.set("port", port)
        if port is None:
            raise ResourcePurged()

        resource.purged = False
        if resource.address and len(port["fixed_ips"]) > 0:
            resource.address = port["fixed_ips"][0]["ip_address"]

        if len(port["fixed_ips"]) > 0:
            subnet = self.get_subnet(None, subnet_id=port["fixed_ips"][0]["subnet_id"])
            if subnet is None:
                ctx.warning(
                    "Unable to find the name of the subnet with id %(subnet_id)s for port %(port_id)s with ip %(ip)s",
                    subnet_id=port["fixed_ips"][0]["subnet_id"],
                    port_id=port["id"],
                    ip=port["fixed_ips"][0]["ip_address"],
                )
            else:
                resource.subnet = subnet["name"]
        else:
            resource.subnet = ""

        if "port_security_enabled" in port:
            resource.portsecurity = port["port_security_enabled"]
            ctx.set("portsecurity", True)
        else:
            ctx.set("portsecurity", False)
            resource.portsecurity = True
            if not resource.portsecurity:
                # Port security is not enabled in the API, but resource wants to disable it.
                ctx.warning(
                    "Ignoring portsecurity is False because extension is not enabled."
                )

        resource.allowed_address_pairs = {}
        if len(port["allowed_address_pairs"]) > 0:
            for pair in port["allowed_address_pairs"]:
                resource.allowed_address_pairs[pair["ip_address"]] = pair["mac_address"]

        resource.name = port["name"]

    def create_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        project_id = ctx.get("project_id")
        network = ctx.get("network")
        vm = ctx.get("vm")
        subnet = self.get_subnet(project_id, name=resource.subnet)
        if subnet is None:
            raise SkipResource(
                "Unable to create host port because the subnet does not exist."
            )

        try:
            body_value = {
                "port": {
                    "admin_state_up": True,
                    "name": resource.name,
                    "network_id": network["id"],
                }
            }

            if resource.address != "" and not resource.dhcp:
                body_value["port"]["fixed_ips"] = [
                    {"subnet_id": subnet["id"], "ip_address": resource.address}
                ]

            if (
                not ctx.contains("portsecurity") or ctx.get("portsecurity")
            ) and not resource.portsecurity:
                body_value["port"]["port_security_enabled"] = False
                body_value["port"]["security_groups"] = None

            if len(resource.allowed_address_pairs) > 0:
                body_value["port"]["allowed_address_pairs"] = []
                for ip, mac in resource.allowed_address_pairs.items():
                    pair = {"ip_address": ip}
                    if mac is not None:
                        pair["mac_address"] = mac

                    body_value["port"]["allowed_address_pairs"].append(pair)

            result = self._neutron.create_port(body=body_value)

            if "port" not in result:
                raise Exception("Unable to create port.")

            port_id = result["port"]["id"]

            # attach it to the host
            vm.interface_attach(port_id, None, None)
        except novaclient.exceptions.Conflict as e:
            raise SkipResource("Host is not ready: %s" % str(e), e)

        ctx.set_created()

    def delete_resource(
        self, ctx: handler.HandlerContext, resource: resources.PurgeableResource
    ) -> None:
        port = ctx.get("port")
        response = self._neutron.delete_port(port["id"])
        ctx.info(
            "Deleted port %(port_id)s with response %(response)s",
            port_id=port["id"],
            response=response,
        )
        ctx.set_purged()

    def update_resource(
        self,
        ctx: handler.HandlerContext,
        changes: dict,
        resource: resources.PurgeableResource,
    ) -> None:
        port = ctx.get("port")
        try:
            if ctx.get("portsecurity") and "portsecurity" in changes:
                if not changes["portsecurity"]["desired"]:
                    self._neutron.update_port(
                        port=port["id"],
                        body={
                            "port": {
                                "port_security_enabled": False,
                                "security_groups": None,
                            }
                        },
                    )
                else:
                    raise SkipResource(
                        "Turning port security on again is not supported."
                    )

                del changes["portsecurity"]

            if "name" in changes:
                self._neutron.update_port(
                    port=port["id"], body={"port": {"name": resource.name}}
                )
                del changes["name"]

            if "allowed_address_pairs" in changes:
                allowed_address_pairs = []
                for ip, mac in resource.allowed_address_pairs.items():
                    pair = {"ip_address": ip}
                    if mac is not None:
                        pair["mac_address"] = mac

                    allowed_address_pairs.append(pair)

                self._neutron.update_port(
                    port=port["id"],
                    body={"port": {"allowed_address_pairs": allowed_address_pairs}},
                )
                del changes["allowed_address_pairs"]

            if len(changes) > 0:
                raise SkipResource("not implemented, %s" % changes)

        except novaclient.exceptions.Conflict as e:
            raise SkipResource("Host is not ready: %s" % str(e))

    @cache(timeout=5)
    def facts(self, ctx, resource):
        ports = self._neutron.list_ports(name=resource.name)

        if "ports" not in ports:
            return {}

        filtered_list = [
            port for port in ports["ports"] if port["name"] == resource.name
        ]

        if len(filtered_list) == 0:
            return {}

        if len(filtered_list) > 1:
            LOGGER.warning("Multiple ports with the same name available!")
            return {}

        port = filtered_list[0]
        facts = {}
        index = 0
        for ip in port["fixed_ips"]:
            facts["ip_address_%d" % index] = ip["ip_address"]
            if index == 0:
                facts["ip_address"] = ip["ip_address"]

        facts["mac_address"] = port["mac_address"]

        return facts


@provider("openstack::SecurityGroup", name="openstack")
class SecurityGroupHandler(OpenStackHandler):
    def _build_current_rules(self, ctx, project_id, security_group):
        rules = []
        for rule in security_group["security_group_rules"]:
            if rule["ethertype"] != "IPv4":
                continue

            current_rule = {"__id": rule["id"]}
            if rule["protocol"] is None:
                current_rule["protocol"] = "all"
            else:
                current_rule["protocol"] = rule["protocol"]

            if rule["remote_ip_prefix"] is not None:
                current_rule["remote_ip_prefix"] = rule["remote_ip_prefix"]

            elif rule["remote_group_id"] is not None:
                rgi = self.get_security_group(
                    ctx, project_id=project_id, group_id=rule["remote_group_id"]
                )
                current_rule["remote_group"] = rgi["name"]

            else:
                current_rule["remote_ip_prefix"] = "0.0.0.0/0"

            current_rule["direction"] = rule["direction"]
            current_rule["port_range_min"] = rule["port_range_min"]
            current_rule["port_range_max"] = rule["port_range_max"]

            rules.append(current_rule)

        return rules

    def read_resource(
        self, ctx: handler.HandlerContext, resource: SecurityGroup
    ) -> None:
        project_id = self.get_project_id(resource, resource.project)
        ctx.set("project_id", project_id)
        sg = self.get_security_group(ctx, project_id=project_id, name=resource.name)

        ctx.set("sg", sg)
        if sg is None:
            raise ResourcePurged()

        resource.purged = False
        resource.description = sg["description"]
        resource.rules = self._build_current_rules(ctx, project_id, sg)

    def _compare_rule(self, old, new):
        old_keys = set([x for x in old.keys() if not x.startswith("__")])
        new_keys = set([x for x in new.keys() if not x.startswith("__")])

        if old_keys != new_keys:
            return False

        for key in old_keys:
            if old[key] != new[key]:
                return False

        return True

    def _diff(self, current, desired):
        changes = OpenStackHandler._diff(self, current, desired)

        if "rules" in changes:
            old_rules = list(changes["rules"]["current"])
            new_rules = list(changes["rules"]["desired"])

            for new_rule in changes["rules"]["desired"]:
                for old_rule in changes["rules"]["current"]:
                    if self._compare_rule(old_rule, new_rule):
                        old_rules.remove(old_rule)
                        new_rules.remove(new_rule)
                        break

            if len(old_rules) == 0 and len(new_rules) == 0:
                del changes["rules"]

        return changes

    def _update_rules(self, group_id, resource, current_rules, desired_rules):
        # # Update rules. First add all new rules, than remove unused rules
        old_rules = list(current_rules)
        # new_rules = [dict(x) for x in desired_rules]
        new_rules = list(desired_rules)

        for new_rule in desired_rules:
            for old_rule in current_rules:
                if self._compare_rule(old_rule, new_rule):
                    old_rules.remove(old_rule)
                    new_rules.remove(new_rule)
                    break

        for new_rule in new_rules:
            new_rule["ethertype"] = "IPv4"
            if "remote_group" in new_rule:
                if new_rule["remote_group"] is not None:
                    # lookup the id of the group
                    groups = self._neutron.list_security_groups(
                        project_id=self.get_project_id(resource, resource.project),
                        name=new_rule["remote_group"],
                    )["security_groups"]
                    if len(groups) == 0:
                        # TODO: log skip rule
                        continue  # Do not update this rule

                    del new_rule["remote_group"]
                    new_rule["remote_group_id"] = groups[0]["id"]

                else:
                    del new_rule["remote_group_id"]

            new_rule["security_group_id"] = group_id

            if new_rule["protocol"] == "all":
                new_rule["protocol"] = None

            try:
                self._neutron.create_security_group_rule(
                    {"security_group_rule": new_rule}
                )
            except exceptions.Conflict:
                LOGGER.exception("Rule conflict for rule %s", new_rule)
                raise

        for old_rule in old_rules:
            try:
                self._neutron.delete_security_group_rule(old_rule["__id"])
            except exceptions.NotFound:
                # TODO: handle this
                pass

    def create_resource(
        self, ctx: handler.HandlerContext, resource: SecurityGroup
    ) -> None:
        sg = self._neutron.create_security_group(
            {
                "security_group": {
                    "name": resource.name,
                    "description": resource.description,
                }
            }
        )
        current_rules = self._build_current_rules(
            ctx, ctx.get("project_id"), sg["security_group"]
        )
        self._update_rules(
            sg["security_group"]["id"], resource, current_rules, resource.rules
        )
        ctx.set_created()

    def delete_resource(
        self, ctx: handler.HandlerContext, resource: SecurityGroup
    ) -> None:
        sg = ctx.get("sg")
        tries = 0
        max_attempts = resource.retries if resource.retries > 0 else 1
        while tries < max_attempts:
            try:
                self._neutron.delete_security_group(sg["id"])
                ctx.set_purged()
                return
            except Exception:
                ctx.info("Delete failed. Waiting and trying again in 5 seconds.")
                time.sleep(resource.wait)
                tries += 1

        raise SkipResource(
            "Deleting the security group failed, probably because it is still in use."
        )

    def update_resource(
        self, ctx: handler.HandlerContext, changes: dict, resource: SecurityGroup
    ) -> None:
        updated = False
        sg = ctx.get("sg")
        if "name" in changes or "description" in changes:
            self._neutron.update_security_group(
                sg["id"],
                {
                    "security_group": {
                        "name": resource.name,
                        "description": resource.description,
                    }
                },
            )
            updated = True

        if "rules" in changes:
            self._update_rules(
                sg["id"],
                resource,
                changes["rules"]["current"],
                changes["rules"]["desired"],
            )
            updated = True

        if updated:
            ctx.set_updated()

    @cache(timeout=5)
    def facts(self, ctx, resource):
        return {}


@provider("openstack::FloatingIP", name="openstack")
class FloatingIPHandler(OpenStackHandler):
    @cache(timeout=10)
    def get_port_id(self, name):
        ports = self._neutron.list_ports(name=name)["ports"]
        if len(ports) == 0:
            return None

        elif len(ports) == 1:
            return ports[0]["id"]
        else:
            raise Exception("Multiple ports found with name %s" % name)

    @cache(timeout=10)
    def get_floating_ip(self, port_id):
        fip = self._neutron.list_floatingips(port_id=port_id)["floatingips"]
        if len(fip) == 0:
            return None

        else:
            return fip[0]["id"]

    def read_resource(self, ctx: handler.HandlerContext, resource: FloatingIP) -> None:
        port_id = self.get_port_id(resource.port)
        ctx.set("port_id", port_id)
        fip = self.get_floating_ip(port_id)
        ctx.set("fip", fip)

        if fip is None:
            raise ResourcePurged()

        resource.purged = False

    def _find_available_fips(self, project_id, network_id):
        available_fips = []
        floating_ips = self._neutron.list_floatingips(
            floating_network_id=network_id, tenant_id=project_id
        )["floatingips"]
        for fip in floating_ips:
            if fip["port_id"] is None:
                available_fips.append(fip)

        return available_fips

    def create_resource(
        self, ctx: handler.HandlerContext, resource: FloatingIP
    ) -> None:
        network_id = self.get_network(None, resource.external_network)["id"]
        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource(
                "Cannot create a floating ip when project id is not yet known."
            )
        ctx.set("project_id", project_id)

        port_id = ctx.get("port_id")
        if network_id is None:
            raise SkipResource("Unable to find external network")

        available_fips = self._find_available_fips(project_id, network_id)
        selected_fip = None
        if len(available_fips) > 0:
            if resource.address is not None:
                for fip in available_fips:
                    if fip["floating_ip_address"] == resource.address:
                        selected_fip = fip
            else:
                selected_fip = available_fips[0]

        if selected_fip:
            self._neutron.update_floatingip(
                selected_fip["id"],
                {"floatingip": {"port_id": port_id, "description": resource.name}},
            )

        else:
            self._neutron.create_floatingip(
                {
                    "floatingip": {
                        "port_id": port_id,
                        "floating_network_id": network_id,
                        "description": resource.name,
                        "floating_ip_address": resource.address,
                    }
                }
            )

        ctx.set_created()

        # Setting fact manually
        for key, value in self.facts(ctx, resource).items():
            ctx.set_fact(key, value)

    def delete_resource(
        self, ctx: handler.HandlerContext, resource: FloatingIP
    ) -> None:
        self._neutron.delete_floatingip(ctx.get("fip"))
        ctx.set_purged()

    def update_resource(
        self, ctx: handler.HandlerContext, changes: dict, resource: FloatingIP
    ) -> None:
        raise SkipResource("Updating a floating ip is not supported")

    @cache(timeout=5)
    def facts(self, ctx, resource):
        port_id = self.get_port_id(resource.port)
        fip = self._neutron.list_floatingips(port_id=port_id)["floatingips"]
        if len(fip) == 0:
            return {}

        else:
            return {"ip_address": fip[0]["floating_ip_address"]}


@dependency_manager
def keystone_dependencies(config_model, resource_model):
    projects = {}
    users = {}
    roles = []
    for _, res in resource_model.items():
        if res.id.entity_type == "openstack::Project":
            if not res.purged:
                projects[res.name] = res

        elif res.id.entity_type == "openstack::User":
            if not res.purged:
                users[res.name] = res

        elif res.id.entity_type == "openstack::Role":
            if not res.purged:
                roles.append(res)

    for role in roles:
        if role.project in projects:
            # can be absent when doing purges
            role.requires.add(projects[role.project])

        if role.user not in users:
            # happens with unmanaged users
            continue

        role.requires.add(users[role.user])


@provider("openstack::Project", name="openstack")
class ProjectHandler(OpenStackHandler):
    def read_resource(self, ctx, resource):
        try:
            project = self._keystone.projects.find(name=resource.name)
            resource.purged = False
            resource.enabled = project.enabled
            resource.description = project.description
            ctx.set("project", project)
        except NotFound:
            raise ResourcePurged()

    def create_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        self._keystone.projects.create(
            resource.name,
            description=resource.description,
            enabled=resource.enabled,
            domain="default",
        )
        ctx.set_created()

    def delete_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        ctx.get("project").delete()
        ctx.set_purged()

    def update_resource(
        self, ctx, changes: dict, resource: resources.PurgeableResource
    ) -> None:
        ctx.get("project").update(
            name=resource.name,
            description=resource.description,
            enabled=resource.enabled,
        )
        ctx.set_updated()

    def facts(self, ctx, resource: Project):
        keystone = self.get_connection(resource)
        try:
            project = keystone.tenants.find(name=resource.name)
            return {"id": project.id, "name": project.name}
        except Exception:
            return {}


@provider("openstack::User", name="openstack")
class UserHandler(OpenStackHandler):
    def read_resource(self, ctx, resource):
        try:
            user = self._keystone.users.find(name=resource.name)
            resource.purged = False
            resource.enabled = user.enabled
            resource.email = user.email
            ctx.set("user", user)

            # if a password is provided (not ""), check if it works otherwise mark it as "***"
            if resource.password != "":
                try:
                    s = keystone_client.Client(
                        auth_url=resource.auth_url,
                        username=resource.name,
                        password=resource.password,
                    )
                    s.authenticate()
                except Exception:
                    resource.password = "***"

        except NotFound:
            raise ResourcePurged()

    def create_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        self._keystone.users.create(
            resource.name,
            password=resource.password,
            email=resource.email,
            enabled=resource.enabled,
        )
        ctx.set_created()

    def delete_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        ctx.get("user").delete()
        ctx.set_purged()

    def update_resource(
        self, ctx, changes: dict, resource: resources.PurgeableResource
    ) -> None:
        user_id = ctx.get("user").id
        if resource.password != "":
            self._keystone.users.update(
                user_id,
                password=resource.password,
                email=resource.email,
                enabled=resource.enabled,
            )
        else:
            self._keystone.users.update(
                user_id, email=resource.email, enabled=resource.enabled
            )
        ctx.set_updated()


@provider("openstack::Role", name="openstack")
class RoleHandler(OpenStackHandler):
    """
    creates roles and user, project, role assocations
    """

    def read_resource(self, ctx, resource):
        # get the role
        role = None
        resource.purged = False
        try:
            role = self._keystone.roles.find(name=resource.role)
        except NotFound:
            ctx.info("Role %(role)s does not exist yet.", role=resource.role)
            resource.purged = True

        try:
            user = self._keystone.users.find(name=resource.user)
        except NotFound:
            raise SkipResource("The user does not exist.")

        try:
            project = self._keystone.projects.find(name=resource.project)
        except NotFound:
            raise SkipResource("The project does not exist.")

        if role is not None:
            try:
                self._keystone.roles.check(role=role, user=user, project=project)
            except Exception:
                resource.purged = True

        ctx.set("role", role)
        ctx.set("user", user)
        ctx.set("project", project)

    def create_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        user = ctx.get("user")
        project = ctx.get("project")
        role = ctx.get("role")

        if role is None:
            ctx.info("Creating Role %(role)s", role=resource.role)
            role = self._keystone.roles.create(resource.role)

        self._keystone.roles.grant(user=user, role=role, project=project)
        ctx.set_created()

    def delete_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        user = ctx.get("user")
        project = ctx.get("project")
        role = ctx.get("role")

        self._keystone.roles.revoke(user=user, role=role, project=project)
        ctx.set_purged()

    def update_resource(
        self, ctx, changes: dict, resource: resources.PurgeableResource
    ) -> None:
        assert False, "This should not happen"


@provider("openstack::Service", name="openstack")
class ServiceHandler(OpenStackHandler):
    def read_resource(self, ctx, resource):
        service = None
        try:
            service = self._keystone.services.find(
                name=resource.name, type=resource.type
            )
            resource.description = service.description
            resource.purged = False
        except NotFound:
            resource.purged = True
            resource.description = None
            resource.name = None
            resource.type = None

        ctx.set("service", service)

    def create_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        self._keystone.services.create(
            resource.name, resource.type, description=resource.description
        )
        ctx.set_created()

    def delete_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        ctx.get("service").delete()
        ctx.set_purged()

    def update_resource(
        self, ctx, changes: dict, resource: resources.PurgeableResource
    ) -> None:
        self._keystone.services.update(
            ctx.get("service"), description=resource.description
        )
        ctx.set_updated()


@provider("openstack::EndPoint", name="openstack")
class EndpointHandler(OpenStackHandler):

    types = {"admin": "admin_url", "internal": "internal_url", "public": "public_url"}

    def read_resource(self, ctx, resource):
        service = None
        for s in self._keystone.services.list():
            if resource.service_id == "%s_%s" % (s.type, s.name):
                service = s

        if service is None:
            raise SkipResource("Unable to find service to which endpoint belongs")

        endpoints = {}
        try:
            endpoints = {
                e.interface: e
                for e in self._keystone.endpoints.list(
                    region=resource.region, service=service
                )
            }
            for k, v in EndpointHandler.types.items():
                setattr(resource, v, endpoints[k].url if k in endpoints else None)

            resource.purged = False
        except NotFound:
            resource.purged = True
            resource.region = None
            resource.internal_url = None
            resource.admin_url = None
            resource.public_url = None

        ctx.set("service", service)
        ctx.set("endpoints", endpoints)

    def create_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        assert False, "Should never get here"

    def delete_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        for endpoint in ctx.get("endpoints"):
            endpoint.delete()

        ctx.set_purged()

    def update_resource(
        self, ctx, changes: dict, resource: resources.PurgeableResource
    ) -> None:
        service = ctx.get("service")
        endpoints = ctx.get("endpoints")

        for k, v in EndpointHandler.types.items():
            if k not in endpoints:
                self._keystone.endpoints.create(
                    service,
                    url=getattr(resource, v),
                    region=resource.region,
                    interface=k,
                )

            elif v in changes:
                self._keystone.endpoints.update(endpoints[k], url=getattr(resource, v))

        ctx.set_updated()
