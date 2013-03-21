from cStringIO import StringIO

from django.conf import settings
from django.core.handlers.base import BaseHandler
from django.core.handlers.wsgi import WSGIRequest
from django.core import signals
from django.db import close_connection
from django.test import RequestFactory
from requests import Response
from requests.cookies import cookiejar_from_dict
from requests.hooks import dispatch_hook
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers

from ssoclient.v2 import V2ApiClient


def get_api_client(request):
    # TODO: configure caching, auth
    api = V2ApiClient(settings.API_HOST + settings.API_URL)
    if (settings.API_USE_INTERNAL
            or request.META['SERVER_NAME'] == "testserver"):
        api.session.mount('http://', DjangoWSGIAdapter(request))
        api.session.mount('https://', DjangoWSGIAdapter(request))
    return api


class SubRequestHandler(BaseHandler):
    """A HTTP Handler for sub-requests.

    Uses the WSGI interface to compose requests, but returns
    the raw HttpResponse object.

    A modified version of django.test.client.ClientHandler.
    """
    def __init__(self, *args, **kwargs):
        super(SubRequestHandler, self).__init__(*args, **kwargs)
        self.load_middleware()

    def __call__(self, environ):
        signals.request_started.send(sender=self.__class__)
        try:
            request = WSGIRequest(environ)
            response = self.get_response(request)
        finally:
            signals.request_finished.disconnect(close_connection)
            signals.request_finished.send(sender=self.__class__)
            signals.request_finished.connect(close_connection)
        return response


class DjangoSubRequester(RequestFactory):

    handler = SubRequestHandler()

    def request(self, **request):
        return self.handler(self._base_environ(**request))


class DjangoWSGIAdapter(object):
    """A requests transport adapter for django.

    Resolves the request internally via django rather that extenally via HTTP.
    To be used when the target url is also hosted by the same django app.
    """

    _encode_body_methods = set(['PATCH', 'POST', 'PUT', 'TRACE'])

    def __init__(self, request):
        super(DjangoWSGIAdapter, self).__init__()
        self.parent_request = request

    def send(self, request, **kwargs):
        django_response = self.get_django_response(request)
        return self.build_response(request, django_response)

    def close(self):
        pass

    def get_django_response(self, request):
        url = request.url
        data = {}
        method = request.method
        kwargs = {}
        if method in self._encode_body_methods:
            if 'Content-Type' in request.headers:
                content_type = request.headers['Content-Type'].split(';', 1)[0]
                kwargs['content_type'] = content_type
            data = request.body

        env = {
            'REMOTE_ADDR': '127.0.0.1',
            'SERVER_NAME': self.parent_request.META['SERVER_NAME'],
            'SERVER_PORT': self.parent_request.META['SERVER_PORT'],
            'wsgi.url_scheme': self.parent_request.META['wsgi.url_scheme'],
        }
        # convert regular headers into django style headers
        headers = request.headers.items()
        env.update(
            ('HTTP_' + k.replace('-', '_').upper(), v) for k, v in headers
        )
        requester = DjangoSubRequester(**env)
        action = getattr(requester, method.lower())
        return action(url, data, **kwargs)

    def build_response(self, req, resp):
        response = Response()

        response.status_code = resp.status_code
        response.headers = CaseInsensitiveDict((k, v) for k, v in resp.items())

        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = StringIO(resp.content)
        response.reason = None

        if isinstance(req.url, bytes):
            response.url = req.url.decode('utf-8')
        else:
            response.url = req.url

        # Convert from django's SimpleCookie to request's CookieJar
        cookiejar_from_dict(resp.cookies, response.cookies)

        # context
        response.request = req
        response.connection = self

        response = dispatch_hook('response', req.hooks, response)
        return response
