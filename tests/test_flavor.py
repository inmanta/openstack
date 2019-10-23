import inmanta
import pytest

def test_flavor(project):
    project.compile("""
import unittest
import openstack
p = openstack::Provider(name="test", connection_url=std::get_env("OS_AUTH_URL"), username=std::get_env("OS_USERNAME"),
                        password=std::get_env("OS_PASSWORD"), tenant=tenant)
flavor=openstack::Flavor(
    name="test"
    ram=1024
    vcpus=4
    disk=10
)
    """)
