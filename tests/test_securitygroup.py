from neutronclient.neutron import client as neutron_client

def test_sg_pre(openstack):
    d1p1 = openstack.get_shared_project()
    d1p2 = openstack.get_project("tenant2")

    def dump_sgs(name, user, project_id = d1p1.project_id):
        connection = user.connection
        nets =  [x.name + " " + x.project_id for x in  connection.network.security_groups(project_id=project_id)]
        print(name, user._username, len(nets), nets)
        return len(nets)

    def dump_sgs_neutron(name, user, project_id = d1p1.project_id):
        n = neutron_client.Client("2.0", session=user.session)
        nets =  [x["name"] + " " + x["project_id"] for x in n.list_security_groups(project_id=project_id)["security_groups"]]
        print(name, user._username, len(nets), nets)
        return len(nets)

    u1 = dump_sgs_neutron("u1 before creation", d1p1._user)
    u2 = dump_sgs_neutron("u2 on u1", d1p2._user, d1p1.project_id)
    u2 = dump_sgs_neutron("before creation", d1p2._user, d1p2.project_id)
    a1 = dump_sgs_neutron("before creation", d1p2._admin)

    u1 = dump_sgs("u1 before creation", d1p1._user)
    u2 = dump_sgs("u2 on u1", d1p2._user, d1p1.project_id)
    u2 = dump_sgs("before creation", d1p2._user, d1p2.project_id)
    a1 = dump_sgs("before creation", d1p2._admin)

    # n1 = d1p1.create_network("for_subnet")

    # s1 = d1p1.create_subnet("subnet", n1.id)

    # assert 1 == dump_subnets("after creation", d1p1._user)

    # d1p1._user.connection.network.delete_subnet(s1.id)

    # assert 0 == dump_subnets("after delete", d1p1._user)