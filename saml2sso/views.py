# Copyright 2011-2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.views.decorators.csrf import csrf_exempt
from saml2idp.views import login_begin, login_init, login_process

# XXX: we should not import webui here
from webui.decorators import sso_login_required


# 'login_begin' must not be wrapped by any other function.
@csrf_exempt
def saml_begin(request):
    return login_begin(request)


@sso_login_required
def saml_init(request, resource, **kwargs):
    return login_init(request, resource, **kwargs)


@sso_login_required
def saml_process(request):
    return login_process(request)
