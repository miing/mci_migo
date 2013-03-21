import uuid

from oops_wsgi import django as oops_wsgi_django


class OOPSWSGIHandler(oops_wsgi_django.OOPSWSGIHandler):
    """
    Custom WSGI Handler that generates oops ids when an error is encountered
    so the ids can be reported to the user.
    """

    def handle_uncaught_exception(self, request, resolver, exc_info):
        # Generate OOPS id early so that we can render the error page
        # right
        # away and not depend on passing thread locals around.
        if 'oops.report' in request.environ:
            unique_id = uuid.uuid4().hex
            request.environ['oops.report']['id'] = "OOPS-%s" % unique_id
        return super(OOPSWSGIHandler, self).handle_uncaught_exception(
            request, resolver, exc_info)

    def __call__(self, environ, start_response):
        def start_response_with_exc_info(status, headers, exc_info=None):
            """Custom start_response callback for wsgi."""
            # This will pass the exception information back to oops_wsgi.  It
            # should not be necessary once
            # https://code.djangoproject.com/ticket/16674 has been merged.
            if exc_info is None:
                exc_info = environ['oops.context'].get('exc_info', None)
            return start_response(status, headers, exc_info)
        return super(OOPSWSGIHandler, self).__call__(
            environ, start_response_with_exc_info)
