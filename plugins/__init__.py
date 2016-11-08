"""
    Copyright 2016 Inmanta

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
import re
import logging
import json
import tempfile
import urllib
import time
import shlex
import subprocess
from http import client

from inmanta.execute.proxy import UnknownException

from inmanta.plugins import plugin
from inmanta.resources import Resource, resource, ResourceNotFoundExcpetion
from inmanta.agent.handler import provider, ResourceHandler, SkipResource, cache
from inmanta.export import dependency_manager

from neutronclient.common import exceptions
from neutronclient.neutron import client as neutron_client

from novaclient import client as nova_client
import novaclient.exceptions

from keystoneclient.auth.identity import v2
from keystoneauth1 import session
from keystoneclient.v2_0 import client as keystone_client
try:
    from keystoneclient.exceptions import NotFound
except ImportError:
    from keystoneclient.openstack.common.apiclient.exceptions import NotFound

# silence a logger
loud_logger = logging.getLogger("requests.packages.urllib3.connectionpool")
loud_logger.propagate = False


LOGGER = logging.getLogger(__name__)
NULL_UUID = "00000000-0000-0000-0000-000000000000"
NULL_ID = "00000000000000000000000000000000"


def get_key_name(exporter, vm):
    return vm.key_pair.name


def get_key_value(exporter, vm):
    return vm.key_pair.public_key


def get_user_data(exporter, vm):
    """
        Return an empty string when the user_data value is unknown
        TODO: this is a hack
    """
    try:
        ua = vm.user_data
    except UnknownException:
        ua = ""
    # if ua is None or ua == "":
    #    raise Exception("User data is required!")
    return ua


OS_FIELDS = ["project", "admin_user", "admin_password", "admin_tenant", "auth_url", "purged", "purge_on_delete"]
OS_MAP = {"project": lambda x, y: y.project.name,
          "admin_user": lambda x, y: y.provider.username,
          "admin_password": lambda x, y: y.provider.password,
          "admin_tenant": lambda x, y: y.provider.tenant,
          "auth_url": lambda x, y: y.provider.connection_url
          }


def get_ports(_, vm):
    ports = []
    for p in vm.ports:
        port = {"name": p.name, "address": None, "network": p.subnet.name, "dhcp": p.dhcp, "index": p.port_index}
        try:
            port["address"] = p.address
        except UnknownException:
            pass
        ports.append(port)

    return ports


@resource("openstack::Host", agent="provider.name", id_attribute="name")
class Host(Resource):
    """
        A virtual machine managed by a hypervisor or IaaS
    """
    fields = OS_FIELDS + ["name", "flavor", "image", "key_name", "user_data", "key_value", "ports",
                          "security_groups"]
    map = {"key_name": get_key_name,
           "key_value": get_key_value,
           "user_data": get_user_data,
           "ports": get_ports,
           "security_groups": lambda _, vm: [x.name for x in vm.security_groups],
           }
    map.update(OS_MAP)


def get_gateway(exporter, router):
    if hasattr(router.ext_gateway, "name"):
        return router.ext_gateway.name

    return ""


@resource("openstack::Network", agent="provider.name", id_attribute="name")
class Network(Resource):
    """
        This class represents a network in neutron
    """
    fields = ("name", "external", "physical_network", "network_type", "segmentation_id",
              "project", "purged", "admin_user", "admin_password", "admin_tenant", "auth_url")
    map = {"project": lambda x, y: y.project.name,
           "admin_user": lambda x, y: y.provider.username,
           "admin_password": lambda x, y: y.provider.password,
           "admin_tenant": lambda x, y: y.provider.tenant,
           "auth_url": lambda x, y: y.provider.connection_url}


@resource("openstack::Subnet", agent="provider.name", id_attribute="name")
class Subnet(Resource):
    """
        This class represent a subnet in neutron
    """
    fields = ("name", "project", "purged", "network_address", "dhcp", "allocation_start",
              "allocation_end", "network", "admin_user", "admin_password", "admin_tenant",
              "auth_url")
    map = {"network": lambda x, y: y.network.name,
           "project": lambda x, y: y.project.name,
           "admin_user": lambda x, y: y.provider.username,
           "admin_password": lambda x, y: y.provider.password,
           "admin_tenant": lambda x, y: y.provider.tenant,
           "auth_url": lambda x, y: y.provider.connection_url}


def get_routes(_, router):
    routes = {route.destination: route.nexthop for route in router.routes}
    return routes


@resource("openstack::Router", agent="provider.name", id_attribute="name")
class Router(Resource):
    """
        This class represent a router in neutron
    """
    fields = ("name", "project", "subnets", "purged", "admin_user", "admin_password",
              "admin_tenant", "auth_url", "gateway", "ports", "routes")
    map = {"subnets": lambda x, y: sorted([subnet.name for subnet in y.subnets]),
           "ports": lambda x, y: [p.name for p in y.ports],
           "routes": get_routes,
           "gateway": get_gateway,
           "project": lambda x, y: y.project.name,
           "admin_user": lambda x, y: y.provider.username,
           "admin_password": lambda x, y: y.provider.password,
           "admin_tenant": lambda x, y: y.provider.tenant,
           "auth_url": lambda x, y: y.provider.connection_url}


@resource("openstack::RouterPort", agent="provider.name", id_attribute="name")
class RouterPort(Resource):
    """
        A port in a router
    """
    fields = ("name", "purged", "admin_user", "admin_password", "admin_tenant", "auth_url", "address", "project",
              "subnet", "router", "network")
    map = {"subnet": lambda x, y: y.subnet.name,
           "network": lambda x, y: y.subnet.network.name,
           "router": lambda x, y: y.router.name,
           "project": lambda x, y: y.project.name,
           "admin_user": lambda x, y: y.provider.username,
           "admin_password": lambda x, y: y.provider.password,
           "admin_tenant": lambda x, y: y.provider.tenant,
           "auth_url": lambda x, y: y.provider.connection_url}


def get_port_address(exporter, port):
    try:
        return port.address
    except UnknownException:
        return ""


@resource("openstack::HostPort", agent="provider.name", id_attribute="name")
class HostPort(Resource):
    """
        A port in a router
    """
    fields = ("name", "purged", "admin_user", "admin_password", "admin_tenant", "auth_url", "address", "project",
              "subnet", "host", "network", "portsecurity", "dhcp")
    map = {"address": get_port_address,
           "subnet": lambda x, y: y.subnet.name,
           "network": lambda x, y: y.subnet.network.name,
           "host": lambda x, y: y.host.name,
           "project": lambda x, y: y.project.name,
           "admin_user": lambda x, y: y.provider.username,
           "admin_password": lambda x, y: y.provider.password,
           "admin_tenant": lambda x, y: y.provider.tenant,
           "auth_url": lambda x, y: y.provider.connection_url}


def security_rules_to_json(exporter, group):
    rules = []
    for rule in group.rules:
        json_rule = {"protocol": rule.ip_protocol,
                     "direction": rule.direction}

        if rule.port > 0:
            json_rule["port_range_min"] = rule.port
            json_rule["port_range_max"] = rule.port

        else:
            json_rule["port_range_min"] = rule.port
            json_rule["port_range_max"] = rule.port

        if json_rule["port_range_min"] == 0:
            json_rule["port_range_min"] = None

        if json_rule["port_range_max"] == 0:
            json_rule["port_range_max"] = None

        try:
            json_rule["remote_ip_prefix"] = rule.remote_prefix
        except Exception:
            pass

        try:
            json_rule["remote_group"] = rule.remote_group
        except Exception:
            pass

        rules.append(json_rule)

    return rules


@resource("openstack::SecurityGroup", agent="provider.name", id_attribute="name")
class SecurityGroup(Resource):
    """
        A security group in an OpenStack tenant
    """
    fields = OS_FIELDS + ["name", "description", "manage_all", "rules"]
    map = {"rules": security_rules_to_json}
    map.update(OS_MAP.copy())


@resource("openstack::FloatingIP", agent="provider.name", id_attribute="name")
class FloatingIP(Resource):
    """
        A floating ip
    """
    fields = OS_FIELDS + ["name", "port", "external_network"]
    map = {"port": lambda _, x: x.port.name,
           "external_network": lambda _, x: x.router.ext_gateway.name,
           }
    map.update(OS_MAP.copy())


@resource("openstack::Project", agent="provider.name", id_attribute="name")
class Project(Resource):
    """
        This class represents a project in keystone
    """
    fields = ("name", "enabled", "description", "admin_token", "url", "purged",
              "admin_user", "admin_password", "admin_tenant", "auth_url", "manage")

    map = {"admin_token": lambda x, y: y.provider.token,
           "url": lambda x, y: os.path.join(y.provider.admin_url, "v2.0/"),
           "admin_user": lambda x, y: y.provider.username,
           "admin_password": lambda x, y: y.provider.password,
           "admin_tenant": lambda x, y: y.provider.tenant,
           "auth_url": lambda x, y: y.provider.connection_url}


@resource("openstack::User", agent="provider.name", id_attribute="name")
class User(Resource):
    """
        A user in keystone
    """
    fields = ("name", "email", "enabled", "password", "admin_token", "url", "purged",
              "admin_user", "admin_password", "admin_tenant", "auth_url")
    map = {"admin_token": lambda x, y: y.provider.token,
           "url": lambda x, y: os.path.join(y.provider.admin_url, "v2.0/"),
           "admin_user": lambda x, y: y.provider.username,
           "admin_password": lambda x, y: y.provider.password,
           "admin_tenant": lambda x, y: y.provider.tenant,
           "auth_url": lambda x, y: y.provider.connection_url}


@resource("openstack::Role", agent="provider.name", id_attribute="role_id")
class Role(Resource):
    """
        A role that adds a user to a project
    """
    fields = ("role_id", "role", "project", "user", "admin_token", "url", "purged",
              "admin_user", "admin_password", "admin_tenant", "auth_url")
    map = {"project": lambda x, obj: obj.project.name,
           "user": lambda x, obj: obj.user.name,
           "admin_token": lambda x, y: y.provider.token,
           "url": lambda x, y: os.path.join(y.provider.admin_url, "v2.0/"),
           "admin_user": lambda x, y: y.provider.username,
           "admin_password": lambda x, y: y.provider.password,
           "admin_tenant": lambda x, y: y.provider.tenant,
           "auth_url": lambda x, y: y.provider.connection_url}


@resource("openstack::Service", agent="provider.name", id_attribute="name")
class Service(Resource):
    """
        A service for which endpoints can be registered
    """
    fields = ("name", "type", "description", "admin_token", "url", "purged",
              "admin_user", "admin_password", "admin_tenant", "auth_url")
    map = {"admin_token": lambda x, y: y.provider.token,
           "url": lambda x, y: os.path.join(y.provider.admin_url, "v2.0/"),
           "admin_user": lambda x, y: y.provider.username,
           "admin_password": lambda x, y: y.provider.password,
           "admin_tenant": lambda x, y: y.provider.tenant,
           "auth_url": lambda x, y: y.provider.connection_url}


@resource("openstack::EndPoint", agent="provider.name", id_attribute="service_id")
class EndPoint(Resource):
    """
        An endpoint for a service
    """
    fields = ("region", "internal_url", "public_url", "admin_url", "service_id", "admin_token",
              "url", "purged", "admin_user", "admin_password", "admin_tenant",
              "auth_url")
    map = {"admin_token": lambda x, y: y.provider.token,
           "url": lambda x, y: os.path.join(y.provider.admin_url, "v2.0/"),
           "admin_user": lambda x, y: y.provider.username,
           "admin_password": lambda x, y: y.provider.password,
           "admin_tenant": lambda x, y: y.provider.tenant,
           "auth_url": lambda x, y: y.provider.connection_url}


@provider("openstack::Host", name="openstack")
class VMHandler(ResourceHandler):
    """
        This class handles managing openstack resources
    """
    __connections = {}
# OS_FIELDS = ["project", "admin_user", "admin_password", "admin_tenant", "auth_url", "purged", "purge_on_delete"]

    def pre(self, resource):
        """
            Setup a connection with neutron
        """
        key = (resource.auth_url, resource.project, resource.admin_user, resource.admin_password)
        if key in VMHandler.__connections:
            self._client, self._neutron = VMHandler.__connections[key]
        else:
            auth = v2.Password(auth_url=resource.auth_url, username=resource.admin_user, password=resource.admin_password,
                               tenant_name=resource.project)
            sess = session.Session(auth=auth)
            self._client = nova_client.Client("2", session=sess)
            self._neutron = neutron_client.Client("2.0", session=sess)
            VMHandler.__connections[key] = (self._client, self._neutron)

    def post(self, resource):
        self._client = None
        self._neutron = None

    @cache(timeout=10)
    def get_vm(self, name):
        server = self._client.servers.list(search_opts={"name": name})

        if len(server) == 0:
            return None

        elif len(server) == 1:
            return server[0]

        else:
            raise Exception("Multiple virtual machines with name %s exist." % name)

    def check_resource(self, resource):
        """
            This method will check what the status of the give resource is on
            openstack.
        """
        current = resource.clone()
        server = self.get_vm(resource.name)

        if server is None:
            current.purged = True

        else:
            current.purged = False
            current.security_groups = [sg.name for sg in server.list_security_group()]
            # The port handler has to handle all network/port related changes

        return current

    def list_changes(self, resource):
        """
            List the changes that are required to the vm
        """
        current = self.check_resource(resource)
        return self._diff(current, resource)

    @cache(timeout=10)
    def _port_id(self, port_name):
        ports = self._neutron.list_ports(name=port_name)
        if len(ports["ports"]) > 0:
            return ports["ports"][0]["id"]

        return None

    @cache(timeout=10)
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
                return None
            nic["net-id"] = network
            if not port["dhcp"] and port["address"] is not None:
                nic["v4-fixed-ip"] = port["address"]
        else:
            nic["port-id"] = port_id

        return nic

    def _build_nic_list(self, ports):
        # build a list of nics for this server based on the index in the ports
        no_sort = sorted([p for p in ports if p["index"] == 0], key=lambda x: x["network"])
        sort = sorted([p for p in ports if p["index"] > 0], key=lambda x: x["index"])

        return [self._create_nic_config(p) for p in sort] + [self._create_nic_config(p) for p in no_sort]

    def do_changes(self, resource):
        changes = self.list_changes(resource)

        # First ensure the key is there.
        # TODO: move this to a specific resource
        keys = {k.name: k for k in self._client.keypairs.list()}
        if resource.key_name not in keys:
            self._client.keypairs.create(resource.key_name, resource.key_value)

        if "purged" in changes:
            if changes["purged"][0]:  # create
                flavor = self._client.flavors.find(name=resource.flavor)
                nics = self._build_nic_list(resource.ports)
                server = self._client.servers.create(resource.name, flavor=flavor.id,
                                                     security_groups=resource.security_groups,
                                                     image=resource.image, key_name=resource.key_name,
                                                     userdata=resource.user_data, nics=nics)
            elif changes["state"][1] == "purged" and changes["state"][0] == "active":
                server = self._client.servers.find(name=resource.name)
                server.delete()

        return True

    @cache(timeout=1)
    def facts(self, resource):
        """
            Get facts about this resource
        """
        LOGGER.debug("Finding facts for %s" % resource.id.resource_str())

        try:
            vm = self.cache.get_or_else(
                key="nova_servers", function=self._client.servers.find, timeout=60, name=resource.name)

            networks = vm.networks

            if resource.network in networks:
                ips = networks[resource.network]
            else:
                ips = []
                for net in networks.values():
                    ips.extend(net)

            facts = {}
            if len(ips) > 1:
                LOGGER.warning("Facts only supports one interface per vm. Only the first interface is reported")

            if len(ips) > 0:
                facts["ip_address"] = ips[0]

                # lookup network details of this ip
                for net, addresses in vm.addresses.items():
                    for addr in addresses:
                        if addr["addr"] == facts["ip_address"]:
                            client = self._neutron

                            subnets = self.cache.get_or_else(
                                key="nova_subnets", function=client.list_subnets, timeout=60, name=net)
                            if "subnets" in subnets and len(subnets["subnets"]) == 1:
                                facts["cidr"] = subnets["subnets"][0]["cidr"]

            return facts

        except Exception:
            return {}


@dependency_manager
def neutron_dependencies(config_model, resource_model):
    projects = {}
    networks = {}
    routers = {}
    subnets = {}

    for _, resource in resource_model.items():
        if resource.id.entity_type == "openstack::Project":
            projects[resource.name] = resource

        elif resource.id.entity_type == "openstack::Network":
            networks[resource.name] = resource

        elif resource.id.entity_type == "openstack::Router":
            routers[resource.name] = resource

        elif resource.id.entity_type == "openstack::Subnet":
            subnets[resource.name] = resource

    # they require the tenant to exist
    for network in networks.values():
        network.requires.add(projects[network.model.project.name])

    for router in routers.values():
        router.requires.add(projects[router.model.project.name])

        # depend on the attached subnets
        for subnet_name in router.subnets:
            router.requires.add(subnets[subnet_name])

    for subnet in subnets.values():
        subnet.requires.add(projects[subnet.model.project.name])

        # also require the network it is attached to
        subnet.requires.add(networks[subnet.model.network.name])


class NeutronHandler(ResourceHandler):
    """
        Holds common routines for all neutron handlers
    """
    __connections = {}

    @classmethod
    def is_available(self, io):
        return True

    def list_changes(self, resource):
        """
            List the changes that are required to the vm
        """
        current = self.check_resource(resource)
        return self._diff(current, resource)

    def _diff(self, current, desired):
        changes = {}

        # check attributes
        for field in desired.__class__.fields:
            current_value = getattr(current, field)
            desired_value = getattr(desired, field)

            if desired_value is not None and current_value is None:
                try:
                    id = getattr(current, field + "_id")
                    converter = getattr(self, "get_%s_id" % field)
                    desired_value = converter(self.get_project_id(desired, desired.project), desired_value)
                    current_value = id
                except AttributeError:
                    pass

            if current_value != desired_value:
                changes[field] = (current_value, desired_value)

        return changes

    def __init__(self, agent, io=None):
        super().__init__(agent, io)

        self._client = None
        self._session = None

    def pre(self, resource):
        """
            Setup a connection with neutron
        """
        key = (resource.auth_url, resource.admin_user, resource.admin_password, resource.admin_tenant)
        if key in NeutronHandler.__connections:
            self._client, self._session = NeutronHandler.__connections[key]
        else:
            auth = v2.Password(auth_url=resource.auth_url, username=resource.admin_user,
                               password=resource.admin_password, tenant_name=resource.admin_tenant)
            self._session = session.Session(auth=auth)
            self._client = neutron_client.Client("2.0", session=self._session)
            NeutronHandler.__connections[key] = (self._client, self._session)

    @cache(ignore=["resource"])
    def get_project_id(self, resource, name):
        """
            Retrieve the id of a project based on the given name
        """
        kc = keystone_client.Client(session=self._session)

        # Fallback for non admin users
        if resource.admin_tenant == name:
            return self._session.get_project_id()

        try:
            tenant = kc.tenants.find(name=name)
            return tenant.id
        except Exception:
            return None

    @cache(timeout=5)
    def get_network_id(self, project_id, name):
        """
            Retrieve the network id based on the name of the network
        """
        if project_id is not None:
            networks = self._client.list_networks(tenant_id=project_id, name=name)
        else:
            networks = self._client.list_networks(name=name)

        if len(networks["networks"]) == 0:
            return None

        elif len(networks["networks"]) > 1:
            raise Exception("Found more than one network with name %s for project %s" % (name, project_id))

        else:
            return networks["networks"][0]["id"]

    @cache(timeout=5)
    def get_subnet_id(self, project_id, name):
        """
            Retrieve the subnet id based on the name of the network
        """
        subnets = self._client.list_subnets(tenant_id=project_id, name=name)

        if len(subnets["subnets"]) == 0:
            return None

        elif len(subnets["subnets"]) > 1:
            raise Exception("Found more than one subnet with name %s for project %s" % (name, project_id))

        else:
            return subnets["subnets"][0]["id"]

    @cache(timeout=5)
    def get_router_id(self, project_id, name):
        """
            Retrieve the router id based on the name of the network
        """
        routers = self._client.list_routers(name=name)

        if len(routers["routers"]) == 0:
            return None

        elif len(routers["routers"]) > 1:
            raise Exception("Found more than one router with name %s for project %s" % (name, project_id))

        else:
            return routers["routers"][0]["id"]

    def get_host_id(self, project_id, name):
        return self.get_host(project_id, name).id

    @cache(timeout=5)
    def get_host(self, project_id, name):
        """
            Retrieve the router id based on the name of the network
        """
        nc = nova_client.Client("2", session=self._session)
        vms = nc.servers.findall(name=name)

        if len(vms) == 0:
            return None

        elif len(vms) > 1:
            raise Exception("Found more than one VM with name %s for project %s" % (name, project_id))

        else:
            return vms[0]

    @cache(timeout=600)
    def get_host_for_id(self, id):
        """
            Retrieve the router id based on the name of the network
        """
        nc = nova_client.Client("2", session=self._session)
        vms = nc.servers.findall(id=id)

        if len(vms) == 0:
            return None

        elif len(vms) > 1:
            raise Exception("Found more than one VM with id %s" % (id))

        else:
            return vms[0]

    def post(self, resource):
        self._client = None


@provider("openstack::Network", name="openstack")
class NetworkHandler(NeutronHandler):

    def check_resource(self, resource):
        """
            Check the state of the resource
        """
        current = resource.clone()
        neutron_version = self.facts(resource)

        if len(neutron_version) > 0:
            current.external = neutron_version["router:external"]
            if resource.physical_network != "":
                current.physical_network = neutron_version["provider:physical_network"]

            if resource.network_type != "":
                current.network_type = neutron_version["provider:network_type"]

            if resource.segmentation_id > 0:
                current.segmentation_id = neutron_version["provider:segmentation_id"]

        else:
            current.purged = True

        return current

    def _create_dict(self, resource: Network, project_id):
        net = {"name": resource.name,
               "tenant_id": project_id,
               "admin_state_up": True}

        if resource.physical_network != "":
            net["provider:physical_network"] = resource.physical_network

        if resource.network_type != "":
            net["provider:network_type"] = resource.network_type

        if resource.segmentation_id > 0:
            net["provider:segmentation_id"] = resource.segmentation_id

        return net

    def do_changes(self, resource: Network) -> bool:
        """
            Enforce the changes
        """
        changes = self.list_changes(resource)

        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource("Cannot create network when project id is not yet known.")

        network_id = self.get_network_id(project_id, resource.name)

        changed = False
        if "purged" in changes:
            if changes["purged"][1] == False:  # create the network
                self._client.create_network({"network": self._create_dict(resource, project_id)})
                changed = True

            elif changes["purged"][1] and not changes["purged"][0]:
                self._client.delete_network(network_id)
                changed = True

        elif len(changes) > 0:
            self._client.update_network(network_id, {"network": {"name": resource.name, "router:external": resource.external}})
            changed = True

        return changed

    def facts(self, resource: Network):
        """
            Get facts about this resource
        """
        networks = self._client.list_networks(name=resource.name)

        if "networks" not in networks:
            return {}

        filtered_list = [net for net in networks["networks"] if net["name"] == resource.name]

        if len(filtered_list) == 0:
            return {}

        if len(filtered_list) > 1:
            LOGGER.warning("Multiple networks with the same name available!")
            return {}

        network = filtered_list[0]
        return network


@provider("openstack::Router", name="openstack")
class RouterHandler(NeutronHandler):

    def check_resource(self, resource):
        """
            Check the state of the resource
        """
        current = resource.clone()
        neutron_version = self.facts(resource)

        if len(neutron_version) > 0:
            current.id = neutron_version["id"]
        else:
            current.id = NULL_UUID
            current.purged = True

        # get a list of all attached subnets
        if current.id != NULL_UUID:
            ext_name = ""
            external_net_id = ""
            if "external_gateway_info" in neutron_version and \
                    neutron_version["external_gateway_info"] is not None:
                external_net_id = neutron_version["external_gateway_info"]["network_id"]

                networks = self._client.list_networks(id=external_net_id)
                if len(networks["networks"]) == 1:
                    ext_name = networks["networks"][0]["name"]

            current.gateway = ext_name

            ports = self._client.list_ports(device_id=current.id)
            subnet_list = []
            for port in ports["ports"]:
                subnets = port["fixed_ips"]
                if port["name"] == "" or port["name"] not in current.ports:
                    for subnet in subnets:
                        if subnet != NULL_UUID:
                            try:
                                subnet_details = self._client.show_subnet(subnet["subnet_id"])
                                if subnet_details["subnet"]["network_id"] != external_net_id:
                                    subnet_list.append(subnet_details["subnet"]["name"])

                            except exceptions.NeutronClientException:
                                pass

            current.subnets = sorted(subnet_list)

            routes = {}
            for route in neutron_version["routes"]:
                routes[route["destination"]] = route["nexthop"]

            current.routes = routes

        else:
            current.gateway = ""
            current.subnets = []
            current.routes = {}

        return current

    def do_changes(self, resource: Router) -> bool:
        """
            Enforce the changes
        """
        changes = self.list_changes(resource)

        changed = False
        deleted = False

        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource("Cannot create network when project id is not yet known.")

        if "purged" in changes:
            if changes["purged"][1] == False:  # create the network
                self._client.create_router({"router": {"name": resource.name, "tenant_id": project_id}})
                changed = True

            elif changes["purged"][1] and not changes["purged"][0]:
                self._client.delete_router(resource.id)
                changed = True
                deleted = True

        elif "name" in changes:
            self._client.update_router(resource.id, {"router": {"name": resource.name}})
            changed = True

        if deleted:
            return changed

        router_facts = self.facts(resource)

        # if the router exists and changes are required in the interfaces, make them
        if "subnets" in changes:
            current = set(changes["subnets"][0])
            to = set(changes["subnets"][1])

            # subnets to add to the router
            for subnet in (to - current):
                # query for the subnet id
                subnet_data = self._client.list_subnets(name=subnet)
                if "subnets" not in subnet_data or len(subnet_data["subnets"]) != 1:
                    raise Exception("Unable to find id of subnet %s" % subnet)

                subnet_id = subnet_data["subnets"][0]["id"]

                self._client.add_interface_router(router=router_facts["id"], body={"subnet_id": subnet_id})

            # subnets to delete
            for subnet in (current - to):
                # query for the subnet id
                subnet_data = self._client.list_subnets(name=subnet)
                if "subnets" not in subnet_data or len(subnet_data["subnets"]) != 1:
                    raise Exception("Unable to find id of subnet %s" % subnet)

                subnet_id = subnet_data["subnets"][0]["id"]

                self._client.remove_interface_router(router=router_facts["id"], body={"subnet_id": subnet_id})

        if "gateway" in changes:
            network_id = self.get_network_id(None, changes["gateway"][1])
            if network_id is None:
                raise Exception("Unable to set router gateway because the gateway network that does not exist.")

            self._client.add_gateway_router(router_facts["id"], {'network_id': network_id})

        if "routes" in changes:
            self._client.update_router(router_facts["id"], {"router": {"routes": [{"nexthop": n, "destination": d}
                                                                                  for d, n in resource.routes.items()]}})

        return changed

    def facts(self, resource: Router):
        """
            Get facts about this resource
        """
        routers = self._client.list_routers(name=resource.name)

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
class SubnetHandler(NeutronHandler):

    def check_resource(self, resource):
        """
            Check the state of the resource
        """
        current = resource.clone()
        neutron_version = self.facts(resource)

        if len(neutron_version) > 0:
            current.id = neutron_version["id"]
            current.network_address = neutron_version["cidr"]
            current.dhcp = neutron_version["enable_dhcp"]
            current.network_id = neutron_version["network_id"]

            pool = neutron_version["allocation_pools"][0]
            if resource.allocation_start != "" and resource.allocation_end != "":  # only change when they are both set
                current.allocation_start = pool["start"]
                current.allocation_end = pool["end"]

        else:
            current.id = 0
            current.purged = True
            current.network_address = ""
            current.network_id = NULL_UUID
            current.allocation_start = ""
            current.allocation_end = ""

        return current

    def do_changes(self, resource: Subnet) -> bool:
        """
            Enforce the changes
        """
        changes = self.list_changes(resource)

        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource("Cannot create network when project id is not yet known.")

        network_id = self.get_network_id(project_id, resource.network)
        if network_id is None:
            raise Exception("Unable to create subnet because of network that does not exist.")

        changed = False
        if "purged" in changes:
            if changes["purged"][1] == False:  # create the network
                body = {"name": resource.name,
                        "network_id": network_id,
                        "enable_dhcp": resource.dhcp,
                        "cidr": resource.network_address,
                        "ip_version": 4,
                        "tenant_id": project_id}

                if len(resource.allocation_start) > 0 and len(resource.allocation_end) > 0:
                    body["allocation_pools"] = [{"start": resource.allocation_start,
                                                 "end": resource.allocation_end}]

                self._client.create_subnet({"subnet": body})
                changed = True

            elif changes["purged"][1] and not changes["purged"][0]:
                self._client.delete_subnet(resource.id)
                changed = True

        elif len(changes) > 0:
            neutron_version = self.facts(resource)
            body = {"subnet": {"enable_dhcp": resource.dhcp}}
            if len(resource.allocation_start) > 0 and len(resource.allocation_end) > 0:
                body["allocation_pools"] = [{"start": resource.allocation_start,
                                             "end": resource.allocation_end}]

            self._client.update_subnet(neutron_version["id"], body)
            changed = True

        return changed

    @cache(timeout=5)
    def facts(self, resource):
        """
            Get facts about this resource
        """
        subnets = self._client.list_subnets(name=resource.name)

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
class RouterPortHandler(NeutronHandler):

    def check_resource(self, resource: RouterPort) -> RouterPort:
        """
            Check the state of the resource
        """
        current = resource.clone()
        neutron_version = self.facts(resource)

        if len(neutron_version) > 0:
            current.id = neutron_version["id"]
            if neutron_version["device_id"] == "":
                current.router_id = NULL_ID
            else:
                current.router_id = neutron_version["device_id"]

            current.network_id = neutron_version["network_id"]

        else:
            current.id = 0
            current.purged = True
            current.subnet_id = NULL_UUID
            current.router_id = NULL_UUID
            current.network_id = NULL_UUID
            current.address = ""

        return current

    def do_changes(self, resource: RouterPort) -> bool:
        """
            Enforce the changes
        """
        changes = self.list_changes(resource)

        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource("Cannot create network when project id is not yet known.")

        subnet_id = self.get_subnet_id(project_id, resource.subnet)
        if subnet_id is None:
            raise SkipResource("Unable to create router port because the subnet does not exist.")

        network_id = self.get_network_id(project_id, resource.network)
        if network_id is None:
            raise SkipResource("Unable to create router port because the network does not exist.")

        router_id = self.get_router_id(project_id, resource.router)
        if router_id is None:
            raise SkipResource("Unable to create router port because the router does not exist.")

        changed = False
        if "purged" in changes:
            if changes["purged"][1] == False:  # create the router port
                body_value = {'port': {
                    'admin_state_up': True,
                    'name': resource.name,
                    'network_id': network_id
                }
                }
                if resource.address != "":
                    body_value["port"]["fixed_ips"] = [{"subnet_id": subnet_id, "ip_address": resource.address}]

                result = self._client.create_port(body=body_value)

                if "port" not in result:
                    raise Exception("Unable to create port.")

                port_id = result["port"]["id"]

                # attach it to the router
                self._client.add_interface_router(router_id, body={"port_id": port_id})
                changed = True

            elif changes["purged"][1] and not changes["purged"][0]:
                # self._client.delete_port(resource.id)
                changed = True

        elif len(changes) > 0:
            # TODO

            changed = True

        return changed

    def facts(self, resource: RouterPort):
        """
            Get facts about this resource
        """
        ports = self._client.list_ports(name=resource.name)

        if "ports" not in ports:
            return {}

        filtered_list = [port for port in ports["ports"] if port["name"] == resource.name]

        if len(filtered_list) == 0:
            return {}

        if len(filtered_list) > 1:
            LOGGER.warning("Multiple ports with the same name available!")
            return {}

        port = filtered_list[0]
        return port


@provider("openstack::HostPort", name="openstack")
class HostPortHandler(NeutronHandler):

    def check_resource(self, resource: HostPort) -> HostPort:
        """
            Check the state of the resource
        """
        current = resource.clone()
        neutron_version = self.facts(resource)
        current.host = None
        current.network = None

        if len(neutron_version) > 0:
            current.id = neutron_version["id"]
            if neutron_version["device_id"] == "":
                current.host_id = NULL_ID
            else:
                current.host_id = neutron_version["device_id"]

            current.network_id = neutron_version["network_id"]
            current.portsecurity = neutron_version["port_security_enabled"]

        else:
            current.id = 0
            current.purged = True
            current.subnet_id = NULL_UUID
            current.router_id = NULL_UUID
            current.network_id = NULL_UUID
            current.address = ""

        return current

    def do_changes(self, resource: HostPort) -> bool:
        """
            Enforce the changes
        """
        changes = self.list_changes(resource)

        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource("Cannot create network when project id is not yet known.")

        subnet_id = self.get_subnet_id(project_id, resource.subnet)
        if subnet_id is None:
            raise SkipResource("Unable to create router port because the subnet does not exist.")

        network_id = self.get_network_id(project_id, resource.network)
        if network_id is None:
            raise SkipResource("Unable to create router port because the network does not exist.")

        vm = self.get_host(project_id, resource.host)
        if vm is None:
            raise SkipResource("Unable to create router port because the router does not exist.")

        try:
            changed = False
            if "purged" in changes:
                if changes["purged"][1] == False:  # create the router port
                    body_value = {'port': {
                        'admin_state_up': True,
                        'name': resource.name,
                        'network_id': network_id
                    }
                    }
                    if resource.address != "":
                        body_value["port"]["fixed_ips"] = [{"subnet_id": subnet_id, "ip_address": resource.address}]

                    result = self._client.create_port(body=body_value)

                    if "port" not in result:
                        raise Exception("Unable to create port.")

                    port_id = result["port"]["id"]

                    # attach it to the host
                    vm.interface_attach(port_id, None, None)
                    changed = True

                elif changes["purged"][1] and not changes["purged"][0]:
                    # TODO
                    raise SkipResource("not implemented")
    #                 interfaces = vm.interface_list()
    #
    #                 vm.interface_detach(portid)
    #                 self._client.delete_port(portid)
                    changed = True
            else:
                port_id = self.facts(resource)["id"]
                if 'host' in changes:
                    # host is wrong
                    fromhost = changes["host"][0]
                    tohost = changes["host"][1]
                    if fromhost != NULL_ID:
                        self.get_host_for_id(fromhost).interface_detach(port_id)
                    self.get_host_for_id(tohost).interface_attach(port_id, None, None)
                    del changes["host"]
                    changed = True
                if 'portsecurity' in changes and changes['portsecurity'][1] == False:
                    self._client.update_port(port=port_id, body={"port":
                                                                 {"port_security_enabled": False,
                                                                  "security_groups": None}})

                    del changes["portsecurity"]
                    changed = True
                if len(changes) > 0:
                    # TODO
                    raise SkipResource("not implemented, %s" % changes)
                    changed = True
        except novaclient.exceptions.Conflict as e:
            raise SkipResource("Host is not ready: %s" % str(e))

        return changed

    @cache(timeout=5)
    def facts(self, resource):
        """
            Get facts about this resource
        """
        ports = self._client.list_ports(name=resource.name)

        if "ports" not in ports:
            return {}

        filtered_list = [port for port in ports["ports"] if port["name"] == resource.name]

        if len(filtered_list) == 0:
            return {}

        if len(filtered_list) > 1:
            LOGGER.warning("Multiple ports with the same name available!")
            return {}

        port = filtered_list[0]
        return port


@provider("openstack::SecurityGroup", name="openstack")
class SecurityGroupHandler(NeutronHandler):
    @cache(timeout=60)
    def get_security_group(self, name):
        """ Get security group details from openstack
        """
        sgs = self._client.list_security_groups(name=name)
        if len(sgs["security_groups"]) == 0:
            return None

        return sgs["security_groups"][0]

    def check_resource(self, resource: SecurityGroup) -> SecurityGroup:
        """ Check the state of the resource
        """
        current = resource.clone()
        sg = self.get_security_group(resource.name)
        if sg is None:
            current.purged = True
            current.rules = []
            return current

        current.description = sg["description"]
        current.__id = sg["id"]
        current.rules = []
        for rule in sg["security_group_rules"]:
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
                current_rule["remote_ip_prefix"] = rule["remote_group_id"]

            else:
                current_rule["remote_ip_prefix"] = "0.0.0.0/0"

            current_rule["direction"] = rule["direction"]
            current_rule["port_range_min"] = rule["port_range_min"]
            current_rule["port_range_max"] = rule["port_range_max"]

            current.rules.append(current_rule)

        return current

    def _compare_rule(self, old, new):
        old_keys = set([x for x in old.keys() if not x.startswith("__")])
        new_keys = set([x for x in new.keys() if not x.startswith("__")])

        if old_keys != new_keys:
            return False

        for key in old_keys:
            if old[key] != new[key]:
                return False

        return True

    def _update_rules(self, group_id, resource, changes):
        # # Update rules. First add all new rules, than remove unused rules
        old_rules = list(changes["rules"][0])
        new_rules = list(changes["rules"][1])

        for new_rule in changes["rules"][1]:
            for old_rule in changes["rules"][0]:
                if self._compare_rule(old_rule, new_rule):
                    old_rules.remove(old_rule)
                    new_rules.remove(new_rule)
                    break

        for new_rule in new_rules:
            new_rule["ethertype"] = "IPv4"
            if "remote_group_id" in new_rule:
                if new_rule["remote_group_id"] is not None:
                    # lookup the id of the group
                    groups = self._client.list_security_groups(name="test")["security_groups"]
                    if len(groups) == 0:
                        # TODO: log skip rule
                        continue  # Do not update this rule

                    new_rule["remote_group_id"] = groups[0]["id"]

                else:
                    del new_rule["remote_group_id"]

            new_rule["security_group_id"] = group_id

            self._client.create_security_group_rule({'security_group_rule': new_rule})

        for old_rule in old_rules:
            self._client.delete_security_group_rule(old_rule["__id"])

    def list_changes(self, resource):
        """
            List the changes that are required to the security group
        """
        current = self.check_resource(resource)
        changes = self._diff(current, resource)

        if "rules" in changes:
            old_rules = list(changes["rules"][0])
            new_rules = list(changes["rules"][1])

            for new_rule in changes["rules"][1]:
                for old_rule in changes["rules"][0]:
                    if self._compare_rule(old_rule, new_rule):
                        old_rules.remove(old_rule)
                        new_rules.remove(new_rule)
                        break

            if len(old_rules) == 0 and len(new_rules) == 0:
                del changes["rules"]

        return changes

    def do_changes(self, resource: SecurityGroup) -> SecurityGroup:
        """ Enforce the changes
        """
        changes = self.list_changes(resource)
        changed = False

        sg_id = None
        if "purged" in changes:
            changed = True
            if changes["purged"][0] == True:  # create
                sg = self._client.create_security_group({"security_group": {"name": resource.name,
                                                                            "description": resource.description}})
                sg_id = sg["security_group"]["id"]
            else:  # purge
                sg = self.get_security_group(resource.name)
                if sg is not None:
                    self._client.delete_security_group(sg["id"])
                    sg_id = sg["id"]

        elif len(changes) > 0:
            sg = self.get_security_group(resource.name)
            if sg is None:
                raise Exception("Unable to modify unexisting security group")

            self._client.update_security_group(sg["id"], {"security_group": {"name": resource.name,
                                                                             "description": resource.description}})
            sg_id = sg["id"]

        if "rules" in changes:
            self._update_rules(sg_id, resource, changes)

        return changed

    @cache(timeout=5)
    def facts(self, resource):
        """ Discover facts about this securitygroup
        """
        return {}


@provider("openstack::FloatingIP", name="openstack")
class FloatingIPHandler(NeutronHandler):
    @cache(timeout=10)
    def get_port_id(self, name):
        ports = self._client.list_ports(name=name)["ports"]
        if len(ports) == 0:
            return None

        elif len(ports) == 1:
            return ports[0]["id"]
        else:
            raise Exception("Multiple ports found with name %s" % name)

    @cache(timeout=10)
    def get_floating_ip(self, port_id):
        fip = self._client.list_floatingips(port_id=port_id)["floatingips"]
        if len(fip) == 0:
            return None

        else:
            return fip["id"]

    def check_resource(self, resource: FloatingIP) -> FloatingIP:
        """ Check the state of the resource
        """
        current = resource.clone()
        port_id = self.get_port_id(resource.port)
        fip = self.get_floating_ip(port_id)
        if fip is None:
            current.purged = True

        else:
            current.purged = False

        return current

    def _find_available_fips(self, project_id, network_id):
        available_fips = []
        floating_ips = self._client.list_floatingips(floating_network_id=network_id, tenant_id=project_id)["floatingips"]
        for fip in floating_ips:
            if fip["port_id"] is None:
                available_fips.append(fip)

        return available_fips

    def do_changes(self, resource: FloatingIP) -> FloatingIP:
        """ Enforce the changes
        """
        changes = self.list_changes(resource)
        changed = False

        project_id = self.get_project_id(resource, resource.project)
        network_id = self.get_network_id(None, resource.external_network)
        port_id = self.get_port_id(resource.port)

        if "purged" in changes:
            if changes["purged"][0]:  # create
                available_fips = self._find_available_fips(project_id, network_id)
                if len(available_fips) > 0:
                    fip_id = available_fips[0]["id"]
                    self._client.update_floatingip(fip_id, {"floatingip": {"port_id": port_id, "description": resource.name}})

                else:
                    self._client.create_floatingip({"floatingip": {"port_id": port_id, "floating_network_id": network_id,
                                                                   "description": resource.name}})

                changed = True

            else:
                # disassociate and purge
                fip_id = self.get_floating_ip(port_id)
                if fip_id is not None:
                    self._client.delete_floatingip(fip_id)

        return changed

    @cache(timeout=5)
    def facts(self, resource):
        """ Discover facts about this floating_ip
        """
        floating_ips = self._client.list_floatingips()

        return {}


@dependency_manager
def keystone_dependencies(config_model, resource_model):
    projects = {}
    users = {}
    roles = []
    for _, resource in resource_model.items():
        if resource.id.entity_type == "openstack::Project":
            projects[resource.name] = resource

        elif resource.id.entity_type == "openstack::User":
            users[resource.name] = resource

        elif resource.id.entity_type == "openstack::Role":
            roles.append(resource)

    for role in roles:
        if role.project not in projects:
            raise Exception("The project %s of role %s is not defined in the model." % (role.project, role.role_id))

        if role.user not in users:
            raise Exception("The user %s of role %s is not defined in the model." % (role.user, role.role_id))

        role.requires.add(projects[role.project])
        role.requires.add(users[role.user])


class KeystoneHandler(ResourceHandler):
    __connections = {}
    """
        Holds common routines for all keystone handlers
    """
    def get_connection(self, resource):
        """
            Get an active connection to keystone
        """
        token = resource.admin_token
        endpoint = resource.url
        if resource.admin_token != "":
            if (endpoint, token) in KeystoneHandler.__connections:
                return KeystoneHandler.__connections[(endpoint, token)]

            conn = keystone_client.Client(endpoint=endpoint, token=token)
            KeystoneHandler.__connections[(endpoint, token)] = conn
            return conn

        else:
            auth = v2.Password(auth_url=resource.auth_url, username=resource.admin_user,
                               password=resource.admin_password, tenant_name=resource.admin_tenant)
            sess = session.Session(auth=auth)
            kc = keystone_client.Client(session=sess)
            return kc

    def list_changes(self, resource):
        """
            List the changes that are required to the vm
        """
        current = self.check_resource(resource)
        return self._diff(current, resource)


@provider("openstack::Project", name="openstack")
class ProjectHandler(KeystoneHandler):
    @classmethod
    def is_available(self, io):
        return True

    def check_resource(self, resource):
        """
            Check the state of the resource
        """
        current = resource.clone()

        keystone = self.get_connection(resource)

        try:
            project = keystone.tenants.find(name=resource.name)

            current.enabled = project.enabled
            current.description = project.description

        except NotFound:
            current.purged = True
            current.enabled = False
            current.description = ""
            current.name = ""

            project = keystone

        return project, current

    def _list_changes(self, resource):
        """
            List the changes that are required to the vm
        """
        project, current = self.check_resource(resource)
        return project, self._diff(current, resource)

    def list_changes(self, resource):
        _, changes = self._list_changes(resource)
        return changes

    def do_changes(self, resource: Project) -> bool:
        """
            Enforce the changes
        """
        if not resource.manage:
            return True

        project, changes = self._list_changes(resource)

        changed = False
        if "purged" in changes:
            if changes["purged"][1] == False:  # create the project
                project.tenants.create(resource.name, description=resource.description, enabled=resource.enabled)
                changed = True

            elif changes["purged"][1] and not changes["purged"][0]:
                project.delete()
                changed = True

        elif len(changes) > 0:
            project.update(name=resource.name, description=resource.description, enabled=resource.enabled)
            changed = True

        return changed

    def facts(self, resource: Project):
        """
            Get facts about this resource
        """
        keystone = self.get_connection(resource)
        try:
            project = keystone.tenants.find(name=resource.name)
            return {"id": project.id, "name": project.name}
        except:
            return {}


@provider("openstack::User", name="openstack")
class UserHandler(KeystoneHandler):
    @classmethod
    def is_available(self, io):
        return True

    def check_resource(self, resource):
        """
            Check the state of the resource
        """
        current = resource.clone()

        keystone = self.get_connection(resource)

        try:
            user = keystone.users.find(name=resource.name)
            current.enabled = user.enabled
            current.email = user.email
        except NotFound:
            current.purged = True
            current.enabled = None
            current.email = None
            current.name = None
            user = keystone

        # if a password is provided (not ""), check if it works otherwise mark it as "***"
        if resource.password != "":
            try:
                keystone_client.Client(auth_url=resource.auth_url, username=resource.name, password=resource.password)
            except:
                current.password = "***"

        return user, current

    def _list_changes(self, resource):
        """
            List the changes that are required to the vm
        """
        user, current = self.check_resource(resource)
        return user, self._diff(current, resource)

    def list_changes(self, resource):
        _, changes = self._list_changes(resource)
        return changes

    def do_changes(self, resource):
        """
            Enforce the changes
        """
        user, changes = self._list_changes(resource)

        changed = False
        if "purged" in changes:
            if changes["purged"][1] == False:  # create a new user
                user.users.create(resource.name, resource.password, email=resource.email, enabled=resource.enabled)
                changed = True

            elif changes["purged"][1] and not changes["purged"][0]:
                user.delete()
                changed = True

        elif len(changes) > 0:
            user.manager.update(user, email=resource.email, enabled=resource.enabled)
            if "password" in changes:
                user.manager.update_password(user, resource.password)
            changed = True

        return changed


@provider("openstack::Role", name="openstack")
class RoleHandler(KeystoneHandler):
    @classmethod
    def is_available(self, io):
        return True

    def check_resource(self, resource):
        """
            Check the state of the resource
        """
        current = resource.clone()

        keystone = self.get_connection(resource)

        # get the role
        role = None
        try:
            role = keystone.roles.find(name=resource.role)
        except NotFound:
            pass

        try:
            user = keystone.users.find(name=resource.user)
            project = keystone.tenants.find(name=resource.project)
        except NotFound:
            # we assume the role does not exist yet and should be created
            current.purged = True
            return None, None, role, current

        found = False
        for r in keystone.roles.roles_for_user(user, project):
            if role is not None and r.id == role.id:
                found = True

        current.purged = not found

        return user, project, role, current

    def _list_changes(self, resource):
        """
            List the changes that are required to the vm
        """
        user, project, role, current = self.check_resource(resource)
        return user, project, role, self._diff(current, resource)

    def list_changes(self, resource):
        _, _, _, changes = self._list_changes(resource)
        return changes

    def do_changes(self, resource):
        """
            Enforce the changes
        """
        user, project, role, changes = self._list_changes(resource)
        changed = False

        keystone = self.get_connection(resource)

        # create the role
        if role is None:
            role = keystone.roles.create(resource.role)
            changed = True

        # create, update or remove
        if "purged" in changes:
            if changes["purged"][1] == False:  # create a new role
                keystone.roles.add_user_role(user, role, project)
                changed = True

            elif changes["purged"][1] and not changes["purged"][0]:
                user.remove_user_role(user, role, project)
                changed = True

        return changed


@provider("openstack::Service", name="openstack")
class ServiceHandler(KeystoneHandler):
    @classmethod
    def is_available(self, io):
        return True

    def check_resource(self, resource):
        """
            Check the state of the resource
        """
        current = resource.clone()
        keystone = self.get_connection(resource)

        try:
            service = keystone.services.find(name=resource.name, type=resource.type)
            current.description = service.description
        except NotFound:
            current.purged = True
            current.description = None
            current.name = None
            current.type = None
            service = keystone

        return service, current

    def _list_changes(self, resource):
        """
            List the changes
        """
        service, current = self.check_resource(resource)
        return service, self._diff(current, resource)

    def list_changes(self, resource):
        _, changes = self._list_changes(resource)
        return changes

    def do_changes(self, resource):
        """
            Enforce the changes
        """
        service, changes = self._list_changes(resource)

        changed = False
        if "purged" in changes:
            if changes["purged"][0]:  # it's new
                service.services.create(resource.name, resource.type, resource.description)
                changed = True

            else:
                service.delete()
                changed = True

        elif len(changes) > 0:
            raise Exception("Updating services is not supported in the API")

        return changed


@provider("openstack::EndPoint", name="openstack")
class EndpointHandler(KeystoneHandler):
    @classmethod
    def is_available(self, io):
        return True

    def check_resource(self, resource):
        """
            Check the state of the resource
        """
        current = resource.clone()

        keystone = self.get_connection(resource)

        service = None
        for s in keystone.services.list():
            if resource.service_id == "%s_%s" % (s.type, s.name):
                service = s

        if service is None:
            raise Exception("Unable to find service to which endpoint belongs")

        try:
            endpoint = keystone.endpoints.find(service_id=service.id)
            current.region = endpoint.region
            current.internal_url = endpoint.internalurl
            current.admin_url = endpoint.adminurl
            current.public_url = endpoint.publicurl

        except NotFound:
            current.purged = True
            current.region = None
            current.internal_url = None
            current.admin_url = None
            current.public_url = None
            endpoint = keystone

        return endpoint, service, current

    def _list_changes(self, resource):
        endpoint, service, current = self.check_resource(resource)
        return endpoint, service, self._diff(current, resource)

    def list_changes(self, resource):
        _, _, changes = self._list_changes(resource)
        return changes

    def do_changes(self, resource):
        """
            Enforce the changes
        """
        endpoint, service, changes = self._list_changes(resource)
        changed = False

        if "purged" in changes:
            if changes["purged"][0]:  # it is new
                endpoint.endpoints.create(region=resource.region, service_id=service.id,
                                          publicurl=resource.public_url, adminurl=resource.admin_url,
                                          internalurl=resource.internal_url)

                changed = True

            else:  # delete
                endpoint.delete()
                changed = True

        elif len(changes) > 0:
            endpoint.manager.delete(endpoint.id)
            endpoint.manager.create(region=resource.region, service_id=service.id,
                                    publicurl=resource.public_url, adminurl=resource.admin_url,
                                    internalurl=resource.internal_url)

            changed = True

        return changed
