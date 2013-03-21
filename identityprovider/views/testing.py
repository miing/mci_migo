# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import get_object_or_404

from identityprovider.models.person import Person


def openid_consumer(request):
    msg = ['Consumer received %s' % request.method]
    args = getattr(request, request.method)
    for arg in sorted(args):
        msg.append("%s:%s" % (arg, args[arg]))
        if arg == 'openid.user_setup_url':
            msg.append('\n')
    return HttpResponse('\n'.join(msg))


def delegate_profile(request, username, version=0):
    person = get_object_or_404(Person, name=username)
    try:
        version = int(version)
    except:
        version = 0
    if person.account is not None and person.account.is_active:
        headers = []
        header_data = {
            'server': settings.SSO_PROVIDER_URL,
            'openid': person.account.openid_identity_url,
        }
        if version in [0, 1]:
            headers += """
            <link rel="openid.server"
                href="%(server)s" />
            <link rel="openid.delegate"
                href="%(openid)s" />"""
        if version in [0, 2]:
            headers += """
            <link rel="openid2.provider"
                href="%(server)s" />
            <link rel="openid2.local_id"
                href="%(openid)s" />
            <meta http-equiv="X-XRDS-Location"
                content="%(openid)s/+xrds" />"""
        headers = "".join(headers) % header_data
    else:
        headers = ""
    return HttpResponse("""
<html>
    <head>
        <title>Test delegation profile for: ~%(name)s</title>
        %(headers)s
    </head>
    <body>
        <h1>Test profile for ~%(name)s</h1>
    </body>
</html>""" % {'name': person.name, 'headers': headers})


def error(request):
    """ Raise an internal server error """
    raise FloatingPointError("This error is a test.  Please ignore.")


# This gives mock & patch a nice easy location to patch a wait into
# the handler.
def dummy_hook():
    return HttpResponse('DONE')


def dummy(request):
    return dummy_hook()
