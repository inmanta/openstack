from inmanta.agent import handler
from inmanta import const


def dryrun(project, prefix, status=const.ResourceState.dry):
    def do_dryrun(resource):

        h = project.get_handler(resource, False)

        assert h is not None

        ctx = handler.HandlerContext(resource)
        h.execute(ctx, resource, True)
        assert ctx.status == status, "expected status %s, got %s" %(status, ctx.status)

        return ctx.changes

    alldr = {name: do_dryrun(resource) for name,resource in project.resources.items() if str(name).startswith(prefix)}    

    return {k:v for k,v in alldr.items() if len(v)>0}

def assert_dr(dr, changes):
    if changes == 0:
        assert len(dr) == 0
    else:
        assert len(dr) == 1
        value = next(dr.values().__iter__())
        assert len(value) == changes, str(value)
        return value