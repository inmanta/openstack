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
import traceback
import logging

from inmanta.execute.proxy import UnknownException
from inmanta.resources import resource, PurgeableResource, ManagedResource
from inmanta import resources
from inmanta.agent import handler
from inmanta.agent.handler import provider, SkipResource, cache, ResourcePurged, CRUDHandler
from inmanta.export import dependency_manager

from neutronclient.common import exceptions
from neutronclient.neutron import client as neutron_client

from novaclient import client as nova_client
import novaclient.exceptions

from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as keystone_client

try:
    from keystoneclient.exceptions import NotFound
except ImportError:
    from keystoneclient.openstack.common.apiclient.exceptions import NotFound

# silence a logger
loud_logger = logging.getLogger("requests.packages.urllib3.connectionpool")
loud_logger.propagate = False


LOGGER = logging.getLogger(__name__)


class OpenstackResource(PurgeableResource, ManagedResource):
    fields = ("project", "admin_user", "admin_password", "admin_tenant", "auth_url")

    @staticmethod
    def get_project(exporter, resource):
        return resource.project.name

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


@resource("openstack::Host", agent="provider.name", id_attribute="name")
class Host(OpenstackResource):
    """
        A virtual machine managed by a hypervisor or IaaS
    """
    fields = ("name", "flavor", "image", "key_name", "user_data", "key_value", "ports", "security_groups")

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
        except UnknownException:
            ua = ""
        return ua

    @staticmethod
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

    @staticmethod
    def get_security_groups(_, vm):
        return [v.name for v in vm.security_groups]


@resource("openstack::Network", agent="provider.name", id_attribute="name")
class Network(OpenstackResource):
    """
        This class represents a network in neutron
    """
    fields = ("name", "external", "physical_network", "network_type", "segmentation_id")


@resource("openstack::Subnet", agent="provider.name", id_attribute="name")
class Subnet(OpenstackResource):
    """
        This class represent a subnet in neutron
    """
    fields = ("name", "network_address", "dhcp", "allocation_start", "allocation_end", "network")

    @staticmethod
    def get_network(_, subnet):
        return subnet.network.name


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
        routes = {route.destination: route.nexthop for route in router.routes}
        return routes

    @staticmethod
    def get_subnets(_, router):
        return sorted([subnet.name for subnet in router.subnets])

    @staticmethod
    def get_ports(_, router):
        return [p.name for p in router.ports]


@resource("openstack::RouterPort", agent="provider.name", id_attribute="name")
class RouterPort(OpenstackResource):
    """
        A port in a router
    """
    fields = ("name", "address", "subnet", "router", "network")

    @staticmethod
    def get_subnet(_, port):
        return port.subnet.name

    @staticmethod
    def get_network(_, port):
        return port.subnet.network.name

    @staticmethod
    def get_router(_, port):
        return port.router.name


@resource("openstack::HostPort", agent="provider.name", id_attribute="name")
class HostPort(OpenstackResource):
    """
        A port in a router
    """
    fields = ("name", "address", "subnet", "host", "network", "portsecurity", "dhcp", "port_index")

    @staticmethod
    def get_address(exporter, port):
        try:
            return port.address
        except UnknownException:
            return ""

    @staticmethod
    def get_subnet(_, port):
        return port.subnet.name

    @staticmethod
    def get_network(_, port):
        return port.subnet.network.name

    @staticmethod
    def get_host(_, port):
        return port.host.name


@resource("openstack::SecurityGroup", agent="provider.name", id_attribute="name")
class SecurityGroup(OpenstackResource):
    """
        A security group in an OpenStack tenant
    """
    fields = ("name", "description", "manage_all", "rules")

    @staticmethod
    def get_rules(exporter, group):
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
                json_rule["remote_group"] = rule.remote_group.name
            except Exception:
                pass

            rules.append(json_rule)
        return rules


@resource("openstack::FloatingIP", agent="provider.name", id_attribute="name")
class FloatingIP(OpenstackResource):
    """
        A floating ip
    """
    fields = ("name", "port", "external_network")

    @staticmethod
    def get_port(_, fip):
        return fip.port.name

    @staticmethod
    def get_external_network(_, fip):
        return fip.external_network.name


class KeystoneResource(PurgeableResource):
    fields = ("admin_token", "url", "admin_user", "admin_password", "admin_tenant", "auth_url")

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


@resource("openstack::Project", agent="provider.name", id_attribute="name")
class Project(KeystoneResource):
    """
        This class represents a project in keystone
    """
    fields = ("name", "enabled", "description", "manage")

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


@dependency_manager
def openstack_dependencies(config_model, resource_model):
    projects = {}
    networks = {}
    routers = {}
    subnets = {}
    vms = {}
    ports = {}
    fips = {}

    for _, res in resource_model.items():
        if res.id.entity_type == "openstack::Project":
            projects[res.name] = res

        elif res.id.entity_type == "openstack::Network":
            networks[res.name] = res

        elif res.id.entity_type == "openstack::Router":
            routers[res.name] = res

        elif res.id.entity_type == "openstack::Subnet":
            subnets[res.name] = res

        elif res.id.entity_type == "openstack::Host":
            vms[res.name] = res

        elif res.id.entity_type == "openstack::HostPort":
            ports[res.name] = res

        elif res.id.entity_type == "openstack::FloatingIP":
            fips[res.name] = res

    # they require the tenant to exist
    for network in networks.values():
        if network.model.project.name in projects:
            network.requires.add(projects[network.model.project.name])

    for router in routers.values():
        if router.model.project.name in projects:
            router.requires.add(projects[router.model.project.name])

        # depend on the attached subnets
        for subnet_name in router.subnets:
            router.requires.add(subnets[subnet_name])

    for subnet in subnets.values():
        subnet.requires.add(projects[subnet.model.project.name])

        # also require the network it is attached to
        subnet.requires.add(networks[subnet.model.network.name])

    for vm in vms.values():
        vm.requires.add(projects[vm.model.project.name])

        for port in vm.ports:
            vm.requires.add(subnets[port["network"]])

    for port in ports.values():
        port.requires.add(projects[port.model.project.name])
        port.requires.add(subnets[port.network])
        port.requires.add(vms[port.host])

    for fip in fips.values():
        fip.requires.add(networks[fip.external_network])
        fip.requires.add(ports[fip.port])


CRED_TIMEOUT = 600
RESOURCE_TIMEOUT = 10


class OpenStackHandler(CRUDHandler):

    @cache(timeout=CRED_TIMEOUT)
    def get_session(self, auth_url, project, admin_user, admin_password):
        auth = v3.Password(auth_url=auth_url, username=admin_user, password=admin_password, project_name=project,
                           user_domain_id="default", project_domain_id="default")
        sess = session.Session(auth=auth)
        return sess

    @cache(timeout=CRED_TIMEOUT)
    def get_nova_client(self, auth_url, project, admin_user, admin_password):
        return nova_client.Client("2.1", session=self.get_session(auth_url, project, admin_user, admin_password))

    @cache(timeout=CRED_TIMEOUT)
    def get_neutron_client(self, auth_url, project, admin_user, admin_password):
        return neutron_client.Client("2.0", session=self.get_session(auth_url, project, admin_user, admin_password))

    @cache(timeout=CRED_TIMEOUT)
    def get_keystone_client(self, auth_url, project, admin_user, admin_password):
        return keystone_client.Client(session=self.get_session(auth_url, project, admin_user, admin_password))

    def pre(self, ctx, resource):
        project = resource.admin_tenant
        self._nova = self.get_nova_client(resource.auth_url, project, resource.admin_user, resource.admin_password)
        self._neutron = self.get_neutron_client(resource.auth_url, project, resource.admin_user,
                                                resource.admin_password)
        self._keystone = self.get_keystone_client(resource.auth_url, project, resource.admin_user, resource.admin_password)

    def post(self, ctx, resource):
        self._nova = None
        self._neutron = None
        self._keystone = None

    def get_project_id(self, resource, name):
        """
            Retrieve the id of a project based on the given name
        """
        # Fallback for non admin users
        if resource.admin_tenant == name:
            session = self.get_session(resource.auth_url, resource.project, resource.admin_user, resource.admin_password)
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
        if project_id is not None:
            query["tenant_id"] = project_id

        if name is not None:
            query["name"] = name
        elif network_id is not None:
            query["network_id"] = network_id
        else:
            raise Exception("Either a name or an id needs to be provided.")

        networks = self._neutron.list_networks(**query)

        if len(networks["networks"]) == 0:
            return None

        elif len(networks["networks"]) > 1:
            raise Exception("Found more than one network with name %s for project %s" % (name, project_id))

        else:
            return networks["networks"][0]

    def get_subnet(self, project_id, name=None, subnet_id=None):
        """
            Retrieve the subnet id based on the name of the network
        """
        if name is not None:
            subnets = self._neutron.list_subnets(tenant_id=project_id, name=name)
        elif subnet_id is not None:
            subnets = self._neutron.list_subnets(tenant_id=project_id, id=subnet_id)
        else:
            raise Exception("Either a name or an id needs to be provided.")

        if len(subnets["subnets"]) == 0:
            return None

        elif len(subnets["subnets"]) > 1:
            raise Exception("Found more than one subnet with name %s for project %s" % (name, project_id))

        else:
            return subnets["subnets"]

    def get_router(self, project_id, name=None, router_id=None):
        """
            Retrieve the router id based on the name of the network
        """
        if name is not None:
            routers = self._neutron.list_routers(tenant_id=project_id, name=name)
        elif router_id is not None:
            routers = self._neutron.list_routers(tenant_id=project_id, id=router_id)
        else:
            raise Exception("Either a name or an id needs to be provided.")

        if len(routers["routers"]) == 0:
            return None

        elif len(routers["routers"]) > 1:
            raise Exception("Found more than one router with name %s for project %s" % (name, project_id))

        else:
            return routers["routers"]

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
            raise Exception("Found more than one VM with name %s for project %s" % (name, project_id))

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


@provider("openstack::Host", name="openstack")
class HostHandler(OpenStackHandler):
    @cache(timeout=10)
    def get_vm(self, ctx, resource):
        if resource.project == resource.admin_tenant:
            servers = self._nova.servers.list(search_opts={"name": resource.name})
        else:
            try:
                project_id = self.get_project_id(resource, resource.project)
                servers = self._nova.servers.list(search_opts={"all_tenants": True, "tenant_id": project_id,
                                                               "name": resource.name})
            except Exception:
                ctx.exception("Unable to retrieve server list with a scoped login on project %(admin_project)s, "
                              "for project %(project)s. This only works with admin credentials.",
                              admin_project=resource.admin_tenant, project=resource.project, traceback=traceback.format_exc())

        if len(servers) == 0:
            return None

        elif len(servers) == 1:
            return servers[0]

        else:
            raise Exception("Multiple virtual machines with name %s exist." % resource.name)

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

    @cache(timeout=60)
    def get_security_group(self, name=None, group_id=None):
        """
            Get security group details from openstack
        """
        if name is not None:
            sgs = self._neutron.list_security_groups(name=name)
        elif group_id is not None:
            sgs = self._neutron.list_security_groups(id=group_id)

        if len(sgs["security_groups"]) == 0:
            return None

        return sgs["security_groups"][0]

    def _create_nic_config(self, port):
        nic = {}
        port_id = self._port_id(port["name"])
        if port_id is None:
            network = self._get_subnet_id(port["network"])
            if network is None:
                raise SkipResource("Network %s not found" % port["network"])
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

    def _build_sg_list(self, security_groups):
        sg_list = []
        for group in security_groups:
            sg = self.get_security_group(name=group)
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
            resource.purged = True

        else:
            resource.purged = False
            resource.security_groups = [sg.name for sg in server.list_security_group()]
            # The port handler has to handle all network/port related changes

        ctx.set("server", server)

    def create_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        if resource.admin_tenant != resource.project:
            ctx.error("The nova API does not allow to create virtual machines in an other project than the one logged into."
                      " Current login %(admin_project)s, requested project %(project)s",
                      admin_project=resource.admin_tenant, project=resource.project)
            raise Exception()

        self._ensure_key(ctx, resource)
        flavor = self._nova.flavors.find(name=resource.flavor)
        nics = self._build_nic_list(resource.ports)
        self._nova.servers.create(resource.name, flavor=flavor.id, userdata=resource.user_data, nics=nics,
                                  security_groups=self._build_sg_list(resource.security_groups),
                                  image=resource.image, key_name=resource.key_name)
        ctx.set_created()

    def delete_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        ctx.get("server").delete()

    def update_resource(self, ctx, changes: dict, resource: resources.PurgeableResource) -> None:
        server = ctx.get("server")

        self._ensure_key(ctx, resource)
        if "security_groups" in changes:
            current = set(changes["security_groups"]["current"])
            desired = set(changes["security_groups"]["desired"])

            for new_rule in (desired - current):
                self._nova.servers.add_security_group(server, new_rule)

            for remove_rule in (current - desired):
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

            # report the first ip of the port with index 1 as "ip_address"
            for port in resource.ports:
                if port["index"] == 1:
                    if port["network"] in networks:
                        ips = networks[port["network"]]
                        facts["ip_address"] = ips[0]

            return facts
        except Exception:
            return {}


@provider("openstack::Network", name="openstack")
class NetworkHandler(OpenStackHandler):
    def read_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource):
        network = self.facts(ctx, resource)

        if len(network) > 0:
            resource.purged = False
            resource.external = network["router:external"]
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
        net = {"name": resource.name, "tenant_id": project_id, "admin_state_up": True}

        if resource.physical_network != "":
            net["provider:physical_network"] = resource.physical_network

        if resource.network_type != "":
            net["provider:network_type"] = resource.network_type

        if resource.segmentation_id > 0:
            net["provider:segmentation_id"] = resource.segmentation_id

        return net

    def create_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource):
        project_id = self.get_project_id(resource, resource.project)
        self._neutron.create_network({"network": self._create_dict(resource, project_id)})
        ctx.set_created()

    def delete_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource):
        network_id = ctx.get("network_id")
        self._neutron.delete_network(network_id)
        ctx.set_purged()

    def update_resource(self, ctx: handler.HandlerContext, changes: dict, resource: resources.PurgeableResource):
        network_id = ctx.get("network_id")
        self._neutron.update_network(network_id, {"network": {"name": resource.name, "router:external": resource.external}})

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
    def read_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        neutron_version = self.facts(ctx, resource)

        if len(neutron_version) > 0:
            ctx.set("neutron", neutron_version)
            resource.purged = False

        else:
            raise ResourcePurged()

        # get a list of all attached subnets
        ext_name = ""
        external_net_id = ""
        if "external_gateway_info" in neutron_version and neutron_version["external_gateway_info"] is not None:
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
                        subnet_details = self._neutron.show_subnet(subnet["subnet_id"])
                        if subnet_details["subnet"]["network_id"] != external_net_id:
                            subnet_list.append(subnet_details["subnet"]["name"])

                    except exceptions.NeutronClientException:
                        pass

        resource.subnets = sorted(subnet_list)

        routes = {}
        for route in neutron_version["routes"]:
            routes[route["destination"]] = route["nexthop"]

        resource.routes = routes

    def create_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource("Cannot create network when project id is not yet known.")

        result = self._neutron.create_router({"router": {"name": resource.name, "tenant_id": project_id}})
        router_id = result["router"]["id"]
        ctx.info("Created router with id %(id)s", id=router_id)
        ctx.set_created()

        if len(resource.subnets) > 0:
            self._update_subnets(router_id, [], resource.subnets)
            ctx.info("Added subnets to router with id %(id)s", id=router_id)

        if resource.gateway is not None and resource.gateway != "":
            self._set_gateway(router_id, resource.gateway)
            ctx.info("Set gateway of router with id %(id)s", id=router_id)

    def delete_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        router_id = ctx.get("neutron")["id"]

        ports = self._neutron.list_ports(device_id=router_id)["ports"]
        for port in ports:
            if port["device_owner"] == "network:router_interface":
                ctx.info("Detatch interface with port id %(port)s from router %(router_id)s",
                         port=port["id"], router_id=router_id)
                self._neutron.remove_interface_router(router=router_id, body={"port_id": port["id"]})

        self._neutron.delete_router(router_id)
        ctx.set_purged()

    def _update_subnets(self, router_id, current, desired):
        current = set(current)
        to = set(desired)

        # subnets to add to the router
        for subnet in (to - current):
            # query for the subnet id
            subnet_data = self._neutron.list_subnets(name=subnet)
            if "subnets" not in subnet_data or len(subnet_data["subnets"]) != 1:
                raise Exception("Unable to find id of subnet %s" % subnet)

            subnet_id = subnet_data["subnets"][0]["id"]
            self._neutron.add_interface_router(router=router_id, body={"subnet_id": subnet_id})

        # subnets to delete
        for subnet in (current - to):
            # query for the subnet id
            subnet_data = self._neutron.list_subnets(name=subnet)
            if "subnets" not in subnet_data or len(subnet_data["subnets"]) != 1:
                raise Exception("Unable to find id of subnet %s" % subnet)

            subnet_id = subnet_data["subnets"][0]["id"]
            self._neutron.remove_interface_router(router=router_id, body={"subnet_id": subnet_id})

    def _set_gateway(self, router_id, network):
        network = self.get_network(None, name=network)
        if network is None:
            raise Exception("Unable to set router gateway because the gateway network that does not exist.")

        self._neutron.add_gateway_router(router_id, {'network_id': network["id"]})

    def update_resource(self, ctx: handler.HandlerContext, changes: dict, resource: resources.PurgeableResource) -> None:
        router_id = ctx.get("neutron")["id"]
        if "name" in changes:
            self._neutron.update_router(router_id, {"router": {"name": resource.name}})
            ctx.set_updated()

        if "subnets" in changes:
            self._update_subnets(router_id, changes["subnets"]["current"], changes["subnets"]["desired"])
            ctx.info("Modified subnets of router with id %(id)s", id=router_id)
            ctx.set_updated()

        if "gateway" in changes:
            self._set_gateway(router_id, resource.gateway)
            ctx.info("Modified gateway of router with id %(id)s", id=router_id)
            ctx.set_updated()

        if "routes" in changes:
            ctx.set_updated()
            self._neutron.update_router(router_id, {"router": {"routes": [{"nexthop": n, "destination": d}
                                                                          for d, n in resource.routes.items()]}})

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
    def read_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        neutron_version = self.facts(ctx, resource)

        if len(neutron_version) > 0:
            resource.purged = False
            resource.id = neutron_version["id"]
            resource.network_address = neutron_version["cidr"]
            resource.dhcp = neutron_version["enable_dhcp"]
            resource.network_id = neutron_version["network_id"]

            pool = neutron_version["allocation_pools"][0]
            if resource.allocation_start != "" and resource.allocation_end != "":  # only change when they are both set
                resource.allocation_start = pool["start"]
                resource.allocation_end = pool["end"]

            ctx.set("neutron", neutron_version)
        else:
            raise ResourcePurged()

    def create_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource("Cannot create network when project id is not yet known.")

        network = self.get_network(project_id, name=resource.network)
        if network is None:
            raise Exception("Unable to create subnet because of network that does not exist.")

        body = {"name": resource.name, "network_id": network["id"], "enable_dhcp": resource.dhcp,
                "cidr": resource.network_address, "ip_version": 4, "tenant_id": project_id}

        if len(resource.allocation_start) > 0 and len(resource.allocation_end) > 0:
            body["allocation_pools"] = [{"start": resource.allocation_start, "end": resource.allocation_end}]

        self._neutron.create_subnet({"subnet": body})
        ctx.set_created()

    def delete_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        neutron = ctx.get("neutron")
        self._neutron.delete_subnet(neutron["id"])

    def update_resource(self, ctx: handler.HandlerContext, changes: dict, resource: resources.PurgeableResource) -> None:
        neutron = ctx.get("neutron")
        body = {"subnet": {"enable_dhcp": resource.dhcp}}
        if len(resource.allocation_start) > 0 and len(resource.allocation_end) > 0:
            body["allocation_pools"] = [{"start": resource.allocation_start,
                                         "end": resource.allocation_end}]

        self._neutron.update_subnet(neutron["id"], body)

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
    def read_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource("Cannot create network when project id is not yet known.")

        neutron_version = self.facts(ctx, resource)
        ctx.set("neutron", neutron_version)
        ctx.set("project_id", project_id)

        router = None
        if len(neutron_version) > 0:
            # Router stuff
            if neutron_version["device_id"] == "":
                resource.router = ""
            else:
                router = self.get_router(None, router_id=neutron_version["device_id"])
                resource.router = router["name"]

            # Network stuff
            network = self.get_network(project_id, network_id=neutron_version["network_id"])
            resource.network = network["name"]
            ctx.set("network", network)

            # IP address / subnet stuff
            subnet = None
            if len(neutron_version["fixed_ips"]) > 1:
                raise Exception("This handler only supports ports that have an address in a single subnet.")
            elif len(neutron_version["fixed_ips"]) == 0:
                resource.subnet = ""
                resource.address = ""
            else:
                subnet = self.get_subnet(project_id, subnet_id=neutron_version["fixed_ips"][0]["subnet_id"])
                resource.subnet = subnet["name"]
                resource.address = neutron_version["fixed_ips"][0]["ip_address"]

            ctx.set("subnet", subnet)

            resource.purged = False
        else:
            raise ResourcePurged()

    def create_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        project_id = ctx.get("project_id")

        network = self.get_network(project_id, name=resource.network)
        if network is None:
            raise SkipResource("Unable to create router port because the network does not exist.")

        subnet = self.get_subnet(project_id, name=resource.subnet)
        if subnet is None:
            raise SkipResource("Unable to create router port because the subnet does not exist.")

        router = self.get_router(project_id, name=resource.router)
        if router is None:
            raise SkipResource("Unable to create router port because the router does not exist.")

        body_value = {'port': {'admin_state_up': True, 'name': resource.name, 'network_id': network["id"]}}
        if resource.address != "":
            body_value["port"]["fixed_ips"] = [{"subnet_id": subnet["id"], "ip_address": resource.address}]

        result = self._neutron.create_port(body=body_value)

        if "port" not in result:
            raise Exception("Unable to create port.")

        port_id = result["port"]["id"]

        # attach it to the router
        self._neutron.add_interface_router(router["id"], body={"port_id": port_id})
        ctx.set_created()

    def delete_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        self._neutron.delete_port(ctx.get("neutron")["id"])
        ctx.set_purged()

    def update_resource(self, ctx: handler.HandlerContext, changes: dict, resource: resources.PurgeableResource) -> None:
        raise SkipResource("Making changes to router ports is not supported.")

    def facts(self, ctx, resource: RouterPort):
        ports = self._neutron.list_ports(name=resource.name)

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
class HostPortHandler(OpenStackHandler):
    def get_port(self, network_id, device_id):
        ports = self._neutron.list_ports(network_id=network_id, device_id=device_id)["ports"]
        if len(ports) > 0:
            return ports[0]
        return None

    def read_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        project_id = self.get_project_id(resource, resource.project)
        if project_id is None:
            raise SkipResource("Cannot create  a host port when project id is not yet known.")
        ctx.set("project_id", project_id)

        network = self.get_network(project_id, resource.network)
        if network is None:
            raise SkipResource("Network %s for port %s not found." % (resource.network, resource.name))
        ctx.set("network", network)

        vm = self.get_host(project_id, resource.host)
        if vm is None:
            raise SkipResource("Unable to create host port because the vm does not exist.")
        ctx.set("vm", vm)

        port = self.get_port(network["id"], vm.id)
        ctx.set("port", port)
        if port is None:
            raise ResourcePurged()

        resource.purged = False
        if not resource.dhcp:
            resource.address = port["fixed_ips"][0]["ip_address"]

        if len(port["fixed_ips"]) > 0:
            subnet = self.get_subnet(project_id, subnet_id=port["fixed_ips"][0]["subnet_id"])
            resource.subnet = subnet["name"]
        else:
            resource.subnet = ""

        resource.portsecurity = port["port_security_enabled"]
        resource.name = port["name"]

    def create_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        project_id = ctx.get("project_id")
        network = ctx.get("network")
        vm = ctx.get("vm")
        subnet = self.get_subnet_id(project_id, name=resource.subnet)
        if subnet is None:
            raise SkipResource("Unable to create host port because the subnet does not exist.")

        try:
            body_value = {'port': {'admin_state_up': True, 'name': resource.name, 'network_id': network["id"]}}

            if resource.address != "" and not resource.dhcp:
                body_value["port"]["fixed_ips"] = [{"subnet_id": subnet["id"], "ip_address": resource.address}]

            if not resource.portsecurity:
                body_value["port"]["port_security_enabled"] = False
                body_value["port"]["security_groups"] = None

            result = self._neutron.create_port(body=body_value)

            if "port" not in result:
                raise Exception("Unable to create port.")

            port_id = result["port"]["id"]

            # attach it to the host
            vm.interface_attach(port_id, None, None)
        except novaclient.exceptions.Conflict as e:
            raise SkipResource("Host is not ready: %s" % str(e), e)

        ctx.set_created()

    def delete_resource(self, ctx: handler.HandlerContext, resource: resources.PurgeableResource) -> None:
        self._neutron.delete_port(ctx.get("port")["id"])
        ctx.set_purged()

    def update_resource(self, ctx: handler.HandlerContext, changes: dict, resource: resources.PurgeableResource) -> None:
        port = ctx.get("port")

        try:
            if "portsecurity" in changes:
                if not changes["portsecurity"]["desired"]:
                    self._neutron.update_port(port=port["id"], body={"port": {"port_security_enabled": False,
                                                                              "security_groups": None}})
                else:
                    raise SkipResource("Turning port security on again is not supported.")

                del changes["portsecurity"]

            if "name" in changes:
                self._neutron.update_port(port=port["id"], body={"port": {"name": resource.name}})
                del changes["name"]

            if len(changes) > 0:
                raise SkipResource("not implemented, %s" % changes)

        except novaclient.exceptions.Conflict as e:
            raise SkipResource("Host is not ready: %s" % str(e))

    @cache(timeout=5)
    def facts(self, ctx, resource):
        ports = self._neutron.list_ports(name=resource.name)

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
class SecurityGroupHandler(OpenStackHandler):
    @cache(timeout=60)
    def get_security_group(self, name=None, group_id=None):
        """
            Get security group details from openstack
        """
        if name is not None:
            sgs = self._neutron.list_security_groups(name=name)
        elif group_id is not None:
            sgs = self._neutron.list_security_groups(id=group_id)

        if len(sgs["security_groups"]) == 0:
            return None

        return sgs["security_groups"][0]

    def read_resource(self, ctx: handler.HandlerContext, resource: SecurityGroup) -> None:
        sg = self.get_security_group(name=resource.name)
        ctx.set("sg", sg)
        if sg is None:
            raise ResourcePurged()

        resource.description = sg["description"]
        resource.rules = []
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
                rgi = self.get_security_group(id=rule["remote_group_id"])
                current_rule["remote_group"] = rgi["name"]

            else:
                current_rule["remote_ip_prefix"] = "0.0.0.0/0"

            current_rule["direction"] = rule["direction"]
            current_rule["port_range_min"] = rule["port_range_min"]
            current_rule["port_range_max"] = rule["port_range_max"]

            resource.rules.append(current_rule)

    def _compare_rule(self, old, new):
        old_keys = set([x for x in old.keys() if not x.startswith("__")])
        new_keys = set([x for x in new.keys() if not x.startswith("__")])

        if old_keys != new_keys:
            return False

        for key in old_keys:
            if old[key] != new[key]:
                return False

        return True

    def _update_rules(self, group_id, resource, current_rules, desired_rules):
        # # Update rules. First add all new rules, than remove unused rules
        old_rules = list(current_rules)
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
                    groups = self._neutron.list_security_groups(name=new_rule["remote_group"])["security_groups"]
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
                self._neutron.create_security_group_rule({'security_group_rule': new_rule})
            except exceptions.Conflict:
                LOGGER.exception("Rule conflict for rule %s", new_rule)
                raise

        for old_rule in old_rules:
            try:
                self._neutron.delete_security_group_rule(old_rule["__id"])
            except exceptions.NotFound:
                # TODO: handle this
                pass

    def _diff(self, current, desired):
        changes = self._diff(current, desired)

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

    def create_resource(self, ctx: handler.HandlerContext, resource: SecurityGroup) -> None:
        sg = self._neutron.create_security_group({"security_group": {"name": resource.name,
                                                                     "description": resource.description}})
        self._update_rules(sg["security_group"]["id"], resource, [], resource.rules)
        ctx.set_created()

    def delete_resource(self, ctx: handler.HandlerContext, resource: SecurityGroup) -> None:
        sg = ctx.get("sg")
        self._neutron.delete_security_group(sg["id"])
        ctx.set_purged()

    def update_resource(self, ctx: handler.HandlerContext, changes: dict, resource: SecurityGroup) -> None:
        sg = ctx.get("sg")
        if "name" in changes or "description" in changes:
            self._neutron.update_security_group(sg["id"], {"security_group": {"name": resource.name,
                                                                              "description": resource.description}})
            ctx.set_updated()

        if "rules" in changes:
            self._update_rules(sg["id"], resource, changes["rules"]["current"], changes["rules"]["desired"])
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
        fip = self.get_floating_ip(port_id)

        if fip is None:
            raise ResourcePurged()

        resource.purged = False
        ctx.set("port_id", port_id)
        ctx.set("fip", fip)

    def _find_available_fips(self, project_id, network_id):
        available_fips = []
        floating_ips = self._neutron.list_floatingips(floating_network_id=network_id, tenant_id=project_id)["floatingips"]
        for fip in floating_ips:
            if fip["port_id"] is None:
                available_fips.append(fip)

        return available_fips

    def create_resource(self, ctx: handler.HandlerContext, resource: FloatingIP) -> None:
        network_id = self.get_network_id(None, resource.external_network)
        project_id = ctx.get("project_id")
        port_id = ctx.get("port_id")
        if network_id is None:
            raise SkipResource("Unable to finx external network")

        available_fips = self._find_available_fips(project_id, network_id)
        if len(available_fips) > 0:
            fip_id = available_fips[0]["id"]
            self._neutron.update_floatingip(fip_id, {"floatingip": {"port_id": port_id, "description": resource.name}})

        else:
            self._neutron.create_floatingip({"floatingip": {"port_id": port_id, "floating_network_id": network_id,
                                                            "description": resource.name}})

        ctx.set_created()

    def delete_resource(self, ctx: handler.HandlerContext, resource: FloatingIP) -> None:
        self._neutron.delete_floatingip(ctx.get("fip")["id"])
        ctx.set_purged()

    def update_resource(self, ctx: handler.HandlerContext, changes: dict, resource: FloatingIP) -> None:
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
            projects[res.name] = res

        elif res.id.entity_type == "openstack::User":
            users[res.name] = res

        elif res.id.entity_type == "openstack::Role":
            roles.append(res)

    for role in roles:
        if role.project not in projects:
            raise Exception("The project %s of role %s is not defined in the model." % (role.project, role.role_id))

        if role.user not in users:
            raise Exception("The user %s of role %s is not defined in the model." % (role.user, role.role_id))

        role.requires.add(projects[role.project])
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
        self._keystone.projects.create(resource.name, description=resource.description, enabled=resource.enabled,
                                       domain="default")
        ctx.set_created()

    def delete_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        ctx.get("project").delete()
        ctx.set_purged()

    def update_resource(self, ctx, changes: dict, resource: resources.PurgeableResource) -> None:
        ctx.get("project").update(name=resource.name, description=resource.description, enabled=resource.enabled)
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
                    s = keystone_client.Client(auth_url=resource.auth_url, username=resource.name, password=resource.password)
                    s.authenticate()
                except Exception:
                    resource.password = "***"

        except NotFound:
            raise ResourcePurged()

    def create_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        self._keystone.users.create(resource.name, password=resource.password, email=resource.email, enabled=resource.enabled)
        ctx.set_created()

    def delete_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        ctx.get("user").delete()
        ctx.set_purged()

    def update_resource(self, ctx, changes: dict, resource: resources.PurgeableResource) -> None:
        user_id = ctx.get("user").id
        if resource.password != "":
            self._keystone.users.update(user_id, password=resource.password, email=resource.email, enabled=resource.enabled)
        else:
            self._keystone.users.update(user_id, email=resource.email, enabled=resource.enabled)
        ctx.set_updated()


@provider("openstack::Role", name="openstack")
class RoleHandler(OpenStackHandler):
    """
        creates roles and user, project, role assocations
    """
    def read_resource(self, ctx, resource):
        # get the role
        role = None
        try:
            self._keystone.users.find(name="bartvb")
            role = self._keystone.roles.find(name=resource.role)
        except NotFound:
            pass

        try:
            user = self._keystone.users.find(name=resource.user)
            project = self._keystone.projects.find(name=resource.project)
        except NotFound:
            raise SkipResource("Either the user or project does not exist.")

        try:
            self._keystone.roles.check(role=role, user=user, project=project)
            resource.purged = False
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
            role = self._keystone.roles.create(resource.role)

        self._keystone.roles.grant(user=user, role=role, project=project)
        ctx.set_created()

    def delete_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        user = ctx.get("user")
        project = ctx.get("project")
        role = ctx.get("role")

        self._keystone.roles.revoke(user=user, role=role, project=project)
        ctx.set_purged()

    def update_resource(self, ctx, changes: dict, resource: resources.PurgeableResource) -> None:
        assert False, "This should not happen"


@provider("openstack::Service", name="openstack")
class ServiceHandler(OpenStackHandler):
    def read_resource(self, ctx, resource):
        service = None
        try:
            service = self._keystone.services.find(name=resource.name, type=resource.type)
            resource.description = service.description
            resource.purged = False
        except NotFound:
            resource.purged = True
            resource.description = None
            resource.name = None
            resource.type = None

        ctx.set("service", service)

    def create_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        self._keystone.services.create(resource.name, resource.type, description=resource.description)
        ctx.set_created()

    def delete_resource(self, ctx, resource: resources.PurgeableResource) -> None:
        ctx.get("service").delete()
        ctx.set_purged()

    def update_resource(self, ctx, changes: dict, resource: resources.PurgeableResource) -> None:
        self._keystone.services.update(ctx.get("service"), description=resource.description)
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
            endpoints = {e.interface: e for e in self._keystone.endpoints.list(region=resource.region, service=service)}
            for k, v in EndpointHandler.types.items():
                setattr(resource, v, endpoints[k] if k in endpoints else None)

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

    def update_resource(self, ctx, changes: dict, resource: resources.PurgeableResource) -> None:
        service = ctx.get("service")
        endpoints = ctx.get("endpoints")

        for k, v in EndpointHandler.types.items():
            if k not in endpoints:
                self._keystone.endpoints.create(service, url=getattr(resource, v), region=resource.region, interface=k)
                ctx.set_created()

            elif v in changes:
                self._keystone.endpoints.update(endpoints[k], url=getattr(resource, v))
                ctx.set_updated()
