# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.utils import simplejson as json

from django.conf import settings
from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt

from identityprovider.readonly import (
    ReadOnlyManager,
    get_server_atts,
    update_server,
)


@staff_member_required
def readonly_admin(request):
    atts = get_server_atts(settings.APP_SERVERS)
    return render_to_response('admin/readonly.html', atts)


@staff_member_required
def readonly_confirm(request, action, appserver=None, conn=None):
    if request.method == 'POST':
        update_server(action, appserver, conn)
        return HttpResponseRedirect('/readonly')
    context = RequestContext(request, {
        'appserver': appserver,
        'action': action,
        'conn': conn,
    })
    return render_to_response('admin/readonly_confirm.html', context)


@csrf_exempt
def readonly_data(request):
    """Provides data about the readonly status of this app server."""
    if request.method != 'POST':
        raise Http404()
    secret = request.POST.get('secret')
    if secret != settings.READONLY_SECRET:
        raise Http404()
    action = request.POST.get('action')
    conn = request.POST.get('conn')
    romanager = ReadOnlyManager()
    if action == 'set':
        romanager.set_readonly()
    elif action == 'clear':
        romanager.clear_readonly()
    elif action == 'enable':
        romanager.clear_failed(conn)
    elif action == 'disable':
        romanager.mark_failed(conn)
    result = {
        'readonly': settings.READ_ONLY_MODE,
        'automatic': romanager.current_readonly_is_automatic(),
        'next_recovery_due': romanager.next_recovery_due(),
    }
    dbs = []
    for conn in romanager.connections:
        dbid = conn['ID']
        dbs.append({'id': dbid, 'failed': romanager.is_failed(dbid)})
    result['connections'] = dbs
    return HttpResponse(json.dumps(result))
