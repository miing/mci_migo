# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

from functools import wraps

from django.conf import settings
from django.core import urlresolvers
from django.http import Http404

from identityprovider import signed
from identityprovider.models import OpenIDRPConfig
from ubuntu_sso_saml import utils as saml_utils


def is_safe_redirect_url(url):
    """Check if 'url' resolves into a valid URL that can be served."""
    try:
        if url.find('?') >= 0:
            url = url[:url.find('?')]
        response = urlresolvers.resolve(url)
    except urlresolvers.Resolver404:
        return False
    if response is None:
        return False
    view, args, kwargs = response
    return True


def get_rpconfig(trust_root):
    alternatives = [trust_root]

    if trust_root.endswith('/'):
        alternatives.append(trust_root[:-1])
    else:
        alternatives.append(trust_root + '/')

    rpconfig = OpenIDRPConfig.objects.filter(trust_root__in=alternatives)
    if len(rpconfig):
        return rpconfig[0]


def get_rpconfig_from_request(request, token):
    rpconfig = None
    if token:  # won't have an rpconfig without a token
        raw_orequest = request.session.get(token, None)
        if raw_orequest:  # is this an actual openid request?
            orequest = signed.loads(raw_orequest, settings.SECRET_KEY)
            rpconfig = get_rpconfig(orequest.trust_root)

    else:
        # this is either a saml request, and can be handled
        # or a plain login attempt, in which case there's nothing else to do
        rpconfig = saml_utils.get_rpconfig_from_request(request)

    return rpconfig


def require_testing_enabled(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        if not getattr(settings, 'TESTING', False):
            raise Http404()
        return func(*args, **kwargs)
    return wrapped
