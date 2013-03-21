# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django import http
from django.template import RequestContext, loader


class ErrorPage(object):
    def __init__(self, status, errormsg=None):
        self.template_name = '%s.html' % status
        self.status_code = status
        self.errormsg = errormsg

    def __call__(self, request):
        template = loader.get_template(self.template_name)
        oopsid = request.environ.get('oops.report', {}).get('id', None)
        atts = {
            'request': request,
            'oopsid': oopsid,
            'errormsg': self.errormsg,
        }
        context = RequestContext(request, atts)
        return http.HttpResponse(template.render(context),
                                 status=self.status_code)

server_error = ErrorPage(500)
page_not_found = ErrorPage(404)
