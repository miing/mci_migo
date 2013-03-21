from __future__ import absolute_import

import copy
import functools

from adminaudit.models import AuditLog
from gargoyle.models import Switch
from gargoyle.nexus_modules import GargoyleModule
from gargoyle.signals import (
    switch_added,
)


def on_switch_added(sender, request, switch, **kwargs):
    AuditLog.create(request.user, switch, 'create')


def audit(func, request_key="key", is_delete=False):
    @functools.wraps(func)
    def wrapper(self, request):
        switch = Switch.objects.get(key=request.POST.get(request_key))
        old_switch = copy.copy(switch)
        # call wrapped function
        response = func(self, request)
        # create log
        if is_delete:
            AuditLog.create(request.user, old_switch, 'delete')
        else:
            # update object after processing
            switch = Switch.objects.get(key=request.POST.get("key"))
            AuditLog.create(request.user, old_switch, 'update',
                            new_object=switch)
        return response
    return wrapper

switch_added.connect(on_switch_added)

# monkeypatch nexus gargoyle module to add auditlog traces
GargoyleModule.update = audit(GargoyleModule.update, request_key="curkey")
GargoyleModule.status = audit(GargoyleModule.status)
GargoyleModule.delete = audit(GargoyleModule.delete, is_delete=True)
GargoyleModule.add_condition = audit(GargoyleModule.add_condition)
GargoyleModule.remove_condition = audit(GargoyleModule.remove_condition)
