# NOTE: Once we switch to Django 1.2, this will no longer be
# necessary, as that version provides a CSRF_FAILURE_VIEW setting for
# this very purpose.

from django.contrib.csrf import middleware as django
from django.shortcuts import render_to_response
from django.template import RequestContext


class CsrfViewMiddleware(django.CsrfViewMiddleware):

    def process_view(self, request, callback, callback_args, callback_kwargs):
        # Django's middleware returns None if everything is okay, or
        # the CSRF error page otherwise.  We intercept the return
        # value, and return our own message.
        r = super(CsrfViewMiddleware, self).process_view(
            request, callback, callback_args, callback_kwargs)
        if r is not None:
            response = render_to_response("403-csrf.html",
                                          RequestContext(request))
            response.status_code = 403
            return response


class CsrfMiddleware(CsrfViewMiddleware, django.CsrfResponseMiddleware):
    pass
