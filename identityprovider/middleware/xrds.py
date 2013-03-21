# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from urlparse import urlparse

from django.http import Http404
from openid.yadis.accept import getAcceptable
from openid.yadis.constants import YADIS_CONTENT_TYPE, YADIS_HEADER_NAME

from django.conf import settings
from django.core.urlresolvers import resolve
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string

from identityprovider.models import Account


class XRDSMiddleware(object):

    def process_request(self, request):
        accept_content = request.META.get('HTTP_ACCEPT', '')
        # getAcceptable guarantees that only two values can be in acceptable
        acceptable = getAcceptable(accept_content,
                                   ['text/html', YADIS_CONTENT_TYPE])
        # Return the XRDS document if it is preferred to text/html.
        for mtype in acceptable:
            if mtype == 'text/html':
                break
            elif mtype == YADIS_CONTENT_TYPE:
                if request.get_full_path().startswith('/+id'):
                    # Special ID response
                    view, args, kwargs = resolve(
                        urlparse(request.get_full_path())[2])
                    account = get_object_or_404(
                        Account, openid_identifier=kwargs['identifier'])
                    if not account.is_active:
                        raise Http404
                    context = {
                        'provider_url': settings.SSO_PROVIDER_URL,
                        'identity_url': account.openid_identity_url,
                    }
                    return self.xrds_response(
                        template='server/person-xrds.xml',
                        context=context)
                else:
                    # Default discovery response
                    extra_headers = {
                        YADIS_HEADER_NAME: '%s+xrds' % settings.SSO_ROOT_URL,
                    }
                    return self.xrds_response(extra_headers=extra_headers)
        return None

    def xrds_response(self, template=None, context=None, extra_headers=None):
        if template is None:
            template = 'server/openidapplication-xrds.xml'
        if context is None:
            context = {
                'endpoint_url': settings.SSO_PROVIDER_URL,
            }
        if extra_headers is None:
            extra_headers = {}
        response = HttpResponse(render_to_string(template, context))
        response['Content-type'] = YADIS_CONTENT_TYPE
        for header in extra_headers:
            response[header] = extra_headers[header]
        return response
