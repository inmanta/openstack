from inmanta.agent import handler
from inmanta import const
from inmanta.protocol import json_encode
from inmanta.resources import Resource
import json



def reload(resource):
        actual = json.loads(json_encode(
            resource.serialize()))
        return Resource.deserialize(actual)

def dryrun_resource(project, resource, status=const.ResourceState.dry):
    h = project.get_handler(resource, False)

    assert h is not None

    ctx = handler.HandlerContext(resource)
    h.execute(ctx, resource, True)
    assert ctx.status == status, "expected status %s, got %s" %(status, ctx.status)

    return ctx.changes

def dryrun(project, prefix, status=const.ResourceState.dry):
    alldr = {name: dryrun_resource(project, resource, status) for name,resource in project.resources.items() if str(name).startswith(prefix)}    

    return {k:v for k,v in alldr.items() if len(v)>0}

def assert_dr(dr, changes):
    if changes == 0:
        assert len(dr) == 0
    else:
        assert len(dr) == 1
        value = next(dr.values().__iter__())
        assert len(value) == changes, str(value)
        return value

def facts(project, resource):
    h = project.get_handler(resource, False)
    assert h is not None
    ctx = handler.HandlerContext(resource)
    return h.check_facts(ctx, resource)


def ib(value:bool):
    """ inmanta boolean: convert python bool to inmanta bool """
    if value:
        return "true"
    else:
        return "false"