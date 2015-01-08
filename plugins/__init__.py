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

from Imp.agent.handler import provider, ResourceHandler

import os, re, logging, json, tempfile, urllib, time

from http import client
from dateutil import parser
import base64, json

LOGGER = logging.getLogger(__name__)

class OpenstackAPI(object):
    """
        This class implements an openstack API
    """
    def __init__(self, auth_url, tenant, username, password):
        self._auth_url = auth_url
        self._tenant = tenant
        self._username = username
        self._password = password

        self._auth_token = None
        self._auth_expire = 0

        self._services = {}

    def _connect(self, url):
        """
            Connect to the given url
        """
        parts = urllib.parse.urlparse(url)
        host, port = parts.netloc.split(":")

        conn = client.HTTPConnection(host, port)

        return (conn, parts.path)

    def _login(self):
        conn, path = self._connect(self._auth_url)


        request = {"auth" : {
                "tenantName" : self._tenant,
                "passwordCredentials" : {
                        "username" : self._username,
                        "password" : self._password
                }
        }}
        conn.request("POST", path + "/tokens", body = json.dumps(request),
            headers = {"Content-Type" : "application/json", "User-Agent" : "imp-agent"})
        res = conn.getresponse()

        if res.code != 200:
            raise Exception("Unable to login at Openstack using %s" % self._auth_url)

        data = json.loads(res.read().decode("utf-8"))

        conn.close()

        if "access" not in data:
            raise Exception("Received invalid response")

        if "token" not in data["access"]:
            raise Exception("No token received in respone")

        # extract token
        self._auth_token = data["access"]["token"]["id"]
        self._auth_expire = parser.parse(data["access"]["token"]["expires"]).timestamp()

        # extract service endpoints
        if "serviceCatalog" in data["access"]:
            for service in data["access"]["serviceCatalog"]:
                if len(service["endpoints"]) > 0:
                    self._services[service["type"]] = service["endpoints"][0]["publicURL"]

    def get_auth_token(self):
        if self._auth_token is None or self._auth_expire + 3600 > time.time():
            self._auth_token = None
            self._auth_expire = 0
            self._login()

        return self._auth_token

    def vm_list(self, name = None):
        """
            List all virtual machines
        """
        auth_token = self.get_auth_token()
        # REQ: curl -i http://dnetcloud.cs.kuleuven.be:8774/v2/5489e39dce68494286419f228d003d0c/servers/detail
        # -X GET -H "X-Auth-Project-Id: bartvb" -H "User-Agent: python-novaclient"
        # -H "Accept: application/json" -H "X-Auth-Token: dc2aca3c37dd4609834e17db55a03d01"

        if "compute" not in self._services:
            raise Exception("Compute service not available")

        compute_url = self._services["compute"] + "/servers/detail"

        conn, path = self._connect(compute_url)

        if name is not None:
            path += "?name=" + name

        conn.request("GET", path, headers = {"Content-Type" : "application/json",
                "User-Agent" : "imp-agent", "X-Auth-Token" : auth_token,
                "X-Auth-Project-Id" : self._tenant})
        res = conn.getresponse()

        if res.code != 200:
            raise Exception("Unable to retrieve server list at Openstack using %s" % compute_url)

        data = json.loads(res.read().decode("utf-8"))

        if "servers" not in data:
            raise Exception("Received invalid response from Openstack")

        servers = {}
        for server in data["servers"]:
            networks = []
            for net,l in server["addresses"].items():
                if len(l) > 0:
                    networks.append((net, l[0]["addr"]))

            servers[server["name"]] = {
                "id" : server["id"],
                "name" : server["name"],
                "properties" : server,
                "status" : server["status"],
                "networks" : networks,
            }

        return servers

    def get_ports(self, device_id = None):
        """
            Get information about the ports of the given device
        """
        auth_token = self.get_auth_token()

        if "network" not in self._services:
            raise Exception("Network service not available")

        port_url = self._services["network"] + "/v2.0/ports.json"

        if device_id is not None:
            port_url += "?device_id=" + device_id

        conn, path = self._connect(port_url)
        conn.request("GET", path, headers = {"Content-Type" : "application/json",
                "User-Agent" : "imp-agent", "X-Auth-Token" : auth_token,
                "X-Auth-Project-Id" : self._tenant})
        res = conn.getresponse()

        if res.code != 200:
            raise Exception("Unable to retrieve port list at Openstack using %s" % port_url)

        data = json.loads(res.read().decode("utf-8"))

        if "ports" not in data:
            raise Exception("Invalid response")

        ports = {}
        for port in data["ports"]:
            ports[port["id"]] = {
                "id" : port["device_id"],
                "admin_state_up" : port["admin_state_up"],
                "ips" : port["fixed_ips"],
                "mac" : port["mac_address"],
            }

        return ports

    def _parse_subnet(self, data):
        subnet_def= {
            "gateway_ip" : data["gateway_ip"],
            "cidr" : data["cidr"]
        }

        return data["id"], subnet_def

    def get_subnets(self, subnet_id = None):
        """
            Get all subnets or a specific subnet
        """
        auth_token = self.get_auth_token()

        if "network" not in self._services:
            raise Exception("Network service not available")

        if subnet_id is None:
            subnet_url = self._services["network"] + "/v2.0/subnets.json"
        else:
            subnet_url = self._services["network"] + "/v2.0/subnets/%s.json" % subnet_id

        conn, path = self._connect(subnet_url)
        conn.request("GET", path, headers = {"Content-Type" : "application/json",
                "User-Agent" : "imp-agent", "X-Auth-Token" : auth_token,
                "X-Auth-Project-Id" : self._tenant})
        res = conn.getresponse()

        if res.code != 200:
            raise Exception("Unable to retrieve subnet list at Openstack using %s" % subnet_url)

        data = json.loads(res.read().decode("utf-8"))

        if "subnets" not in data and "subnet" not in data:
            raise Exception("Invalid response")

        subnets = {}

        if "subnet" in data:
            _id, s = self._parse_subnet(data["subnet"])
            subnets[_id] = s

        else:
            for subnet in data["subnets"]:
                _id, s = self._parse_subnet(subnet)

                subnets[_id] = s

        return subnets

    def get_keypairs(self):
        """
            Get the deployed keypairs
        """
        auth_token = self.get_auth_token()

        if "compute" not in self._services:
            raise Exception("Compute service not available")

        _url = self._services["compute"] + "/os-keypairs"

        conn, path = self._connect(_url)
        conn.request("GET", path, headers = {"Content-Type" : "application/json",
                "User-Agent" : "imp-agent", "X-Auth-Token" : auth_token,
                "X-Auth-Project-Id" : self._tenant})
        res = conn.getresponse()

        if res.code != 200:
            raise Exception("Unable to retrieve keypair list at Openstack using %s" % _url)

        data = json.loads(res.read().decode("utf-8"))

        if "keypairs" not in data:
            raise Exception("Recevied a response without keypairs")

        keypairs = {}
        for keypair in data["keypairs"]:
            kp = keypair["keypair"]
            keypairs[kp["name"]] = {
                "fingerprint" : kp["fingerprint"],
                "public_key" : kp["public_key"],
            }

        return keypairs

    def add_keypair(self, name, public_key_data):
        """
        Add a new keypair
        """
        auth_token = self.get_auth_token()

        if "compute" not in self._services:
            raise Exception("Compute service not available")

        _url = self._services["compute"] + "/os-keypairs"

        body = json.dumps({"keypair" : {
            "public_key" : public_key_data,
            "name" : name
        }}).encode()

        conn, path = self._connect(_url)
        conn.request("POST", path, headers = {"Content-Type" : "application/json",
                "User-Agent" : "imp-agent", "X-Auth-Token" : auth_token,
                "X-Auth-Project-Id" : self._tenant}, body = body)
        res = conn.getresponse()

        if res.code != 200:
            raise Exception("Unable to add keypair to Openstack using %s" % _url)

    def get_flavors(self):
        """
        Get a list of all the flavors indexed on their id
        """
        auth_token = self.get_auth_token()

        if "compute" not in self._services:
            raise Exception("Compute service not available")

        _url = self._services["compute"] + "/flavors/detail"

        conn, path = self._connect(_url)
        conn.request("GET", path, headers = {"Content-Type" : "application/json",
                "User-Agent" : "imp-agent", "X-Auth-Token" : auth_token,
                "X-Auth-Project-Id" : self._tenant})
        res = conn.getresponse()

        if res.code != 200:
            raise Exception("Unable to get flavor list from Openstack using %s" % _url)

        data = json.loads(res.read().decode("utf-8"))

        if "flavors" not in data:
            return {}

        flavors = {}
        for fl in data["flavors"]:
            flavors[fl["id"]] = fl

        return flavors

    def boot(self, name, flavor, image, key_name, user_data):
        """
        Boot the virtual machine
        """
        auth_token = self.get_auth_token()

        if "compute" not in self._services:
            raise Exception("Compute service not available")

        _url = self._services["compute"] + "/servers"

        if user_data is not None and len(user_data) > 0:
            user_data = base64.encodestring(user_data.encode())

        body = {"server" : {
            "name" : name,
            "flavorRef" : flavor,
            "key_name" : key_name,
            "imageRef" : image,
            "user_data" : user_data,
            "max_count" : 1,
            "min_count" : 1,
        }}

        conn, path = self._connect(_url)
        conn.request("POST", path, headers = {"Content-Type" : "application/json",
                "User-Agent" : "imp-agent", "X-Auth-Token" : auth_token,
                "X-Auth-Project-Id" : self._tenant}, body = json.dumps(body).encode())
        res = conn.getresponse()

        if res.code < 200 or res.code > 299:
            raise Exception("Unable to boot server %s on Openstack using %s (%s)" % (name, _url, res.read()))

@provider("vm::Host", name = "openstack")
class VMHandler(ResourceHandler):
    """
        This class handles managing openstack resources
    """
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
        os_api = OpenstackAPI(resource.iaas_config["url"], resource.iaas_config["tenant"],
                        resource.iaas_config["username"], resource.iaas_config["password"])

        vm_state = {}

        vm_list = os_api.vm_list(resource.name)

        # how the vm doing
        if resource.name in vm_list:
            vm_state["vm"] = vm_list[resource.name]["status"]
        else:
            vm_state["vm"] = None

        # check if the key is there
        keys = os_api.get_keypairs()

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

        if vm_state["vm"] is None:
            changes["vm"] = resource

        return changes

    def do_changes(self, resource):
        """
            Enact the changes
        """
        changes = self.list_changes(resource)

        if len(changes) > 0:
            LOGGER.debug("Making changes to resource %s" % resource.id)

            os_api = OpenstackAPI(resource.iaas_config["url"], resource.iaas_config["tenant"],
                resource.iaas_config["username"], resource.iaas_config["password"])

            if "key" in changes:
                os_api.add_keypair(changes["key"][0], changes["key"][1])

            if "vm" in changes:
                # find the flavor ref
                flavor = 0
                for _id, fl in os_api.get_flavors().items():
                    if fl["name"] == resource.flavor:
                        flavor = int(_id)

                if flavor <= 0:
                    raise Exception("Flavor %s does not exist for vm %s" % (resource.flavor, resource))

                os_api.boot(resource.name, flavor, resource.image, resource.key_name, resource.user_data)

            return True

    def facts(self, resource):
        """
            Get facts about this resource
        """
        LOGGER.debug("Finding facts for %s" % resource.id.resource_str())
        
        OS_api = OpenstackAPI(resource.iaas_config["url"], resource.iaas_config["tenant"],
                              resource.iaas_config["username"], resource.iaas_config["password"])

        all_status = OS_api.vm_list()

        if len(all_status) == 0:
            return {}

        ports = {}
        for port_id,port_data in OS_api.get_ports().items():
            port_data["port_id"] = port_id

            if port_data["id"] not in ports:
                ports[port_data["id"]] = []

            ports[port_data["id"]].append(port_data)

        facts = {}
        subnet_cache = {}
        for host, properties in all_status.items():
            host_facts = properties["properties"]
            del(properties["properties"])
            host_facts.update(properties)

            if properties["id"] in ports:
                rows = ports[properties["id"]][0]

                if len(ports[properties["id"]]) > 1:
                    LOGGER.warning("Facts only supports one interface per vm. Only the first interface is reported")

                host_facts["mac_address"] = rows["mac"]
                host_facts["ip_address"] = rows["ips"][0]["ip_address"]
                subnet_id = rows["ips"][0]["subnet_id"]

                if subnet_id not in subnet_cache:
                    subnet_cache[subnet_id] = OS_api.get_subnets(subnet_id)[subnet_id]

                host_facts["cidr"] = subnet_cache[subnet_id]["cidr"]
                host_facts["gateway_ip"] = subnet_cache[subnet_id]["gateway_ip"]

                from iplib import CIDR
                o = CIDR(host_facts["cidr"])

                host_facts["netmask"] = str(o.nm)


            facts["vm::Host[%s,name=%s]" % (resource.id.agent_name, host)] = host_facts

        if resource.id.resource_str() in facts:
            return facts[resource.id.resource_str()]
        return {}
