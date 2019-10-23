import inmanta

def test_flavor(project):
    project.compile("""
import openstack

provider = openstack::Provider(name="test", connection_url=std::get_env("test"), username=std::get_env("test"),
                        password=std::get_env("test"), tenant="test")
flavor=openstack::Flavor(
    provider=provider,
    name="test",
    ram=1024,
    vcpus=4,
    disk=10
)
""")
