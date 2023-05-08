# Changelog

## v3.8.10 - 2023-05-08

- Convert constraints in requirements.txt file

## v3.8.9 - 2023-04-04


## v3.8.8 - 2023-04-04


## v3.8.7 - 2023-02-02


## v3.8.6 - 2023-02-02
- Dropped outdated requirements

# 3.8.3
- Add default null value to mac address

# 3.7.11
- Remove pytest.ini and move its logic to pyproject.toml

# 3.7.10
- Add pytest.ini file and set asyncio_mode to auto

# 3.7.7
- Use conditional requirement for inmanta-dev-dependencies package

# 3.7.5
- Fix the bug that makes the `openstack::Image` handler hang when the newly created image doesn't enter the `active` status.

# 3.7.3
- openstack::FloatingIP resource set its ip_address fact on creation

# 3.7.2
- Fix wait condition on delete of openstack::VirtualMachine

# 3.7.1
- Ensure correct detection of deleted HostPorts (#286)

# 3.7.0
- Add purge_on_delete option on the Host entity
# 3.6.13
- Tune caching to prevent double creation of VM's
# 3.6.12
- Update inmanta-dev-dependencies package
# 3.6.11
- Add setuptools-rust dependency required to build the cryptography package.

# 3.6.10
- Pin PyOpenssl for compatibility with openssl 1.0.2

# 3.6.9
- Remove transitive dependencies

# 3.6.8
- Use inmanta-dev-dependencies package

# 3.6.7
- Pin cryptography dependency to the correct version (inmanta/infra-tickets#93)

# 3.6.6
- Downgrade cryptography to maintain compatibility with openssl 1.0.2 (inmanta/infra-tickets#93)

# 3.6.5
- Remove the importlib-resources dependency

# 3.6.4
- Remove the prettytable dependency.

# 3.6.3
- Fix type object 'resource' has no attribute 'project'

# 3.6.2
- Fix type object 'resource' has no attribute 'project'

# 3.6.1
- Fix scoping issue on SecurityGroup resource (# 184)

# 3.6.0
- Add support to disable SSL verification (# 152)

# 3.5.6
- Raise a `PluginException` when `find_flavor` fails to find a matching flavor.

# 3.5.5
- Ensure a hostport gets deleted before the associated VM (#79)

# 3.5.4
- Start the packstack VM via pytest

# 3.5.3
- Pin dependencies using ~=

# 3.5.2
- Pin transitive dependencies

# 3.5.1
- Fix problem where the vm_state variable is referenced before assignment

# 3.5.0
- Added support to disable the gateway IP of a subnet

# 3.4.1
- use new relation syntax (#65)

# 3.4.0
- set gateway_ip on subnet by default to null
- fix caching of find_image when name is used
- close requests session of keystone library

# 3.3.2
- fixed dependency manager mixing up identical objects in different providers (#48)

# 3.3.1
- added examples folder

# 3.3.0
- added improved caching for find_image
- added an OpenStack image resource, for add OS images to OpenStack
- Changed send_event default value to true from false

# 3.2.0
- Added support for flavors
- fix updates/creation for host with DHCP and fixed ip

# 3.1.1
- added cache to improve find_flavor performance
- allow model compilation to continue if openstack is unavailable
