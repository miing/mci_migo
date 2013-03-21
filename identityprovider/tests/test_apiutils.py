from django.utils import simplejson as json
from django.conf.urls.defaults import patterns, url
from django.http import HttpResponse
from django.test.client import RequestFactory
from django.views.decorators.csrf import csrf_exempt
import requests

from identityprovider.tests.utils import (
    SSOBaseTestCase,
    SSOBaseUnittestTestCase,
    patch_settings,
)

from identityprovider.apiutils import (
    get_api_client,
    DjangoWSGIAdapter,
)


class GetApiClientTestCase(SSOBaseUnittestTestCase):

    def assert_django_adapters(self, api, request):
        http = api.session.adapters['http://']
        self.assertTrue(isinstance(http, DjangoWSGIAdapter))
        self.assertEqual(http.parent_request, request)
        https = api.session.adapters['https://']
        self.assertTrue(isinstance(https, DjangoWSGIAdapter))
        self.assertEqual(https.parent_request, request)

    def test_api_client_uses_internal_config(self):
        request = RequestFactory().post('/')
        request.META['SERVER_NAME'] = 'blah'
        with patch_settings(API_USE_INTERNAL=True):
            api = get_api_client(request)
        self.assert_django_adapters(api, request)

    def test_api_client_uses_internal_with_test_client(self):
        request = RequestFactory().post('/')
        api = get_api_client(request)
        self.assert_django_adapters(api, request)


@csrf_exempt
def testview(request):
    """Serializes the request data back as a json response, for inspection"""
    data = {
        'GET': request.GET,
        'COOKIES': request.COOKIES,
        'META': dict((k, v) for k, v in request.META.items()
                     if k not in ('wsgi.input', 'wsgi.errors'))
    }
    if request.META['CONTENT_TYPE'] == 'application/json':
        data['POST'] = json.loads(request.read())
    else:
        data['POST'] = request.POST
    return HttpResponse(
        content=json.dumps(data),
        content_type='application/json'
    )

urlpatterns = patterns('', url(r'^test', testview))


class DjangoWSGIAdapterTestCase(SSOBaseTestCase):

    urls = 'identityprovider.tests.test_apiutils'
    factory = RequestFactory(**{
        'SERVER_NAME': "apitest",
        'SERVER_PORT': "667",
        'wsgi.url_scheme': 'https',
    })

    def assert_meta(self, meta):
        self.assertEqual(meta['REMOTE_ADDR'], '127.0.0.1')
        self.assertEqual(meta['SERVER_NAME'], 'apitest')
        self.assertEqual(meta['SERVER_PORT'], '667')
        self.assertEqual(meta['wsgi.url_scheme'], 'https')

    def setUp(self):
        super(DjangoWSGIAdapterTestCase, self).setUp()
        self.session = requests.session()
        self.original_request = self.factory.post('/')
        self.session.mount('http://', DjangoWSGIAdapter(self.original_request))

    def test_django_wsgi_adaptor_get(self):
        response = self.session.get(
            'http://abc/test?a=1',
            headers={
                'Accept': 'application/json',
                'X-Custom-Header': 'Hi',
            },
            cookies={'test': 'cookie'}
        )
        data = response.json()
        get = data['GET']
        self.assertEqual(get['a'], '1')
        self.assertEqual(data['POST'], {})
        self.assert_meta(data['META'])
        self.assertEqual(data['META']['HTTP_X_CUSTOM_HEADER'], 'Hi')
        self.assertEqual(data['COOKIES']['test'], 'cookie')

    def test_django_wsgi_adaptor_post_json(self):
        response = self.session.post(
            'http://abc/test',
            data=json.dumps({'a': 1}),
            headers={
                'Accept': 'application/json',
                'X-Custom-Header': 'Hi',
                'Content-Type': 'application/json'
            },
            cookies={'test': 'cookie'}
        )
        data = response.json()
        self.assertEqual(data['GET'], {})
        self.assertEqual(data['POST']['a'], 1)
        self.assert_meta(data['META'])
        self.assertEqual(data['META']['HTTP_CONTENT_TYPE'], 'application/json')
        self.assertEqual(data['META']['CONTENT_TYPE'], 'application/json')
        self.assertEqual(data['META']['HTTP_X_CUSTOM_HEADER'], 'Hi')
        self.assertEqual(data['COOKIES']['test'], 'cookie')
