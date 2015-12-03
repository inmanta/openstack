"""
    Copyright 2015 Impera

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    Contact: bart@impera.io
"""

import os
import re
import logging
import tempfile
import time

from impera.agent.handler import provider, ResourceHandler
from impera.plugins.base import plugin

from keystoneclient.auth.identity import v2
from keystoneclient import session
from novaclient import client as nova_client
from neutronclient.neutron import client as neutron_client

LOGGER = logging.getLogger(__name__)


@plugin
def parse_logdestination(remote_logging : "string") -> "list":
    m = re.match("(?P<proto>[^:]+)://(?P<host>[^:]+):(?P<port>[0-9]+)", remote_logging)
    if m is not None:
        if m.group("proto") != "tcp":
            raise Exception("Only tcp is supported for now")

        return [m.group("host"), m.group("port")]

    return ["localhost", 5959]


@provider("vm::Host", name = "openstack")
class VMHandler(ResourceHandler):
    """
        This class handles managing openstack resources
    """
    __connections = {}
    def pre(self, resource):
        """
            Setup a connection with neutron
        """
        key = (resource.iaas_config["url"], resource.iaas_config["tenant"], resource.iaas_config["username"],
               resource.iaas_config["password"])
        if key in VMHandler.__connections:
            self._client = VMHandler.__connections[key]
        else:
            auth = v2.Password(auth_url=resource.iaas_config["url"], username=resource.iaas_config["username"],
                               password=resource.iaas_config["password"], tenant_name=resource.iaas_config["tenant"])
            sess = session.Session(auth=auth)
            self._client = nova_client.Client("2", session=sess)
            VMHandler.__connections[key] = self._client

    def post(self, resource):
        self._client = None

    def available(self, resource):
        """
            This handler is available to all virtual machines that have type set to openstack in their iaas_config.
        """
        return "type" in resource.iaas_config and resource.iaas_config["type"] == "openstack"

    def check_resource(self, resource):
        """
            This method will check what the status of the give resource is on
            openstack.
        """
        LOGGER.debug("Checking state of resource %s" % resource)
        vm_state = {}
        vm_list = {s.name: s for s in self._client.servers.list()}

        # how the vm doing
        if resource.name in vm_list:
            vm_state["vm"] = "active"
            vm_state["id"] = vm_list[resource.name].id
        else:
            vm_state["vm"] = "purged"

        # check if the key is there
        keys = {k.name: k for k in self._client.keypairs.list()}

        # TODO: also check the key itself
        if resource.key_name in keys:
            vm_state["key"] = True
        else:
            vm_state["key"] = False

        return vm_state

    def list_changes(self, resource):
        """
            List the changes that are required to the vm
        """
        vm_state = self.check_resource(resource)
        LOGGER.debug("Determining changes required to resource %s" % resource.id)

        changes = {}

        if not vm_state["key"]:
            changes["key"] = (resource.key_name, resource.key_value)

        purged = "active"
        if resource.purged:
            purged = "purged"

        if vm_state["vm"] != purged:
            changes["state"] = (vm_state["vm"], purged)

        if "id" in vm_state:
            changes["id"] = (vm_state["id"], vm_state["id"])

        return changes

    def do_changes(self, resource):
        """
            Enact the changes
        """
        changes = self.list_changes(resource)

        if len(changes) > 0:
            LOGGER.debug("Making changes to resource %s" % resource.id)
            if "key" in changes:
                self._client.keypairs.create(changes["key"][0], changes["key"][1])

            if "state" in changes:
                if changes["state"][0] == "purged" and changes["state"][1] == "active":
                    flavor = self._client.flavors.find(name=resource.flavor)
                    network = self._client.networks.find(human_id=resource.network)

                    server = self._client.servers.create(resource.name, flavor=flavor.id,
                                                         image=resource.image, key_name=resource.key_name,
                                                         userdata=resource.user_data, nics=[{"net-id": network.id}])

                elif changes["state"][1] == "purged" and changes["state"][0] == "active":
                    server = self._client.servers.find(name=resource.name)
                    server.delete()

            if "id" in changes:
                client = neutron_client.Client("2.0", auth_url=resource.iaas_config["url"],
                                               username=resource.iaas_config["username"],
                                               password=resource.iaas_config["password"],
                                               tenant_name=resource.iaas_config["tenant"])

                ports = client.list_ports(device_id=changes["id"])
                if "ports" in ports and len(ports["ports"]) > 0:
                    port = ports["ports"][0]
                    client.update_port(port=port["id"], body={"port":
                                                              {"port_security_enabled": False,
                                                               "security_groups": None}})

            return True

    def facts(self, resource):
        """
            Get facts about this resource
        """
        LOGGER.debug("Finding facts for %s" % resource.id.resource_str())

        try:
            vm = self._client.servers.find(name=resource.name)
            ips = []
            for net in vm.networks.values():
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
                            client = neutron_client.Client("2.0", auth_url=resource.iaas_config["url"],
                                                  username=resource.iaas_config["username"],
                                                  password=resource.iaas_config["password"],
                                                  tenant_name=resource.iaas_config["tenant"])

                            subnets = client.list_subnets(name=net)
                            if "subnets" in subnets and len(subnets["subnets"]) == 1:
                                facts["cidr"] = subnets["subnets"][0]["cidr"]

            return facts

        except Exception:
            return {}
