from openstack import connection
import conftest

def test_openstack_sdk_connect(session):
    conn = connection.Connection(
        session=session,
        identity_interface='public')
    projects = conn.identity.projects()
    assert len([x for x in projects]) != 0


def test_get_own_project_and_domain(session):
    conn = connection.Connection(
        session=session,
        identity_interface='public')
    
    myproject = conn.current_project.id

    project = conn.get_project(myproject)
    
    assert project.name is not None
    assert project.domain_id is not None

    domain = conn.get_domain(project.domain_id)

    assert domain.name is not None

def test_get_own_project_and_domain_2(session):
    conn = connection.Connection(
        session=session,
        identity_interface='public')
    
    myproject = conn.current_project.id

    project = conn.identity.get_project(myproject)
    assert project.name is not None
    assert project.domain_id is not None

    domain = conn.identity.get_domain(project.domain_id)
    assert domain.name is not None

SHARED_FIXTURE = "shared_fixture"
SHARED_DOMAIN = "shared_domain"

def test_fixture(openstack):
    name = "shared_fixture"

    actual_name=conftest.PREFIX+name

    myproject = openstack.get_project(name)

    project = openstack.admin.connection.get_project(actual_name)
    assert project is not None

    #for x in myproject._admin.connection..servers():
    #     print(x, type(x), dir(x))

    # for x in myproject._admin.connection.compute.servers():
    #     print(x, type(x), dir(x))



def test_network_isolation(openstack):
    d1p1 = openstack.get_project(SHARED_FIXTURE)
    d2p1 = openstack.get_project(SHARED_FIXTURE+"2", domain=SHARED_DOMAIN)

    d1p1._user.connection.network.create_network(
        project_id = d1p1.project_id,
        name="test_net_1"
    )

    d2p1._user.connection.network.create_network(
        project_id = d2p1.project_id,
        name="test_net_1"
    )

    # rules discovered
    # 1-admins see all networks, across domains
    # 2-users see public networks across domains 
    # 3-users see networks in their own project

    def dump_networks(name, user, connection=None):
        if connection is None:
            connection = user.connection
        nets =  [x.name + " " + x.project_id for x in  connection.network.networks()]
        print(name, user._username, len(nets), nets)
        return len(nets)

    baseline = dump_networks("superadmin", d1p1._super_admin)

    d1p1admin = dump_networks("d1p1 admin", d1p1._admin)
    assert baseline == d1p1admin
    
    #user => public + 1
    d1p1user = dump_networks("d1p1 user",  d1p1._user)
    public_networks = d1p1user-1

    d2p1admin = dump_networks("d2p1 admin", d2p1._admin)
    assert baseline == d2p1admin
    d2p1user = dump_networks("d2p1 user",  d2p1._user)

    assert d2p1user == public_networks+1

    d2p1.grant(d1p1._user)

    d1p1user2 = dump_networks("d1p1 user Sec",  d1p1._user)
    assert d1p1user2 == public_networks+1

    d1p1user2plus = dump_networks("d1p1 user Sec Two",  d1p1._user, d1p1._user.connection_for_project(d2p1.project_id))
    assert d1p1user2plus == public_networks+1


import threading
def test_threading_problem(openstack):
    project = openstack.get_project(SHARED_FIXTURE)
    print(threading.active_count())
    project._admin.connection
    project._user.connection
    print(threading.active_count())
    project._user.connection.identity
    project._user.connection.network.networks()
    print(threading.active_count())
    project._user.connection.identity
    project._user.connection.network.networks()
    print(threading.active_count())
    project._user.connection.task_manager.stop()
    project._admin.connection.task_manager.stop()
    print(threading.active_count())
    project._user.connection.task_manager.join()
    project._admin.connection.task_manager.join()
    print(threading.active_count())
    project._user.connection.identity.task_manager.stop()
    project._user.connection.identity.task_manager.join()
    print(threading.active_count())
    project._user.connection.network.task_manager.stop()
    project._user.connection.network.task_manager.join()
    print(threading.enumerate())