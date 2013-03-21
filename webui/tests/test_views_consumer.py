# encoding: utf-8
# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from urllib import quote_plus

from django.core.urlresolvers import reverse
from mock import patch
from openid import fetchers
from openid.consumer import consumer
from openid.consumer.discover import OpenIDServiceEndpoint, OPENID_2_0_TYPE
from openid.message import (OPENID1_URL_LIMIT, IDENTIFIER_SELECT)
from openid.yadis.constants import YADIS_CONTENT_TYPE

from identityprovider.tests.utils import SSOBaseTestCase, patch_settings
from identityprovider.views import server

import webui.views.consumer

from webui.views.consumer import (
    SREG_OPTIONAL,
    SREG_REQUIRED,
    get_base_url,
    to_regular_dict,
    render_index_page,
)


class MockFetcher(fetchers.Urllib2Fetcher):

    called = False

    def fetch(self, url, body=None, headers=None):
        MockFetcher.called = True
        return super(MockFetcher, self).fetch(url, body, headers)


class DummyRequest(object):
    def __init__(self, META):
        self.META = META


class DummyDjangoRequest(object):
    def __init__(self):
        self.META = {
            'HTTP_HOST': "localhost",
            'SCRIPT_NAME': "http://localhost",
            'SERVER_PROTOCOL': "http",
        }
        self.POST = {
            'openid_identifier': "http://localhost/+id/abcd123",
        }
        self.session = {}


class BaseTestCase(SSOBaseTestCase):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        fetcher_module = webui.views.consumer.fetchers
        old_fetcher = fetcher_module.getDefaultFetcher().fetcher
        self.mock = MockFetcher()
        fetcher_module.setDefaultFetcher(self.mock)
        self.addCleanup(fetcher_module.setDefaultFetcher, old_fetcher)

    def assert_message_in_response(self, response, msg):
        for m in response.context['messages']:
            if msg in m.message:
                break  # the else block will not be executed
        else:
            self.fail('Message %r is not present in the given response.' % msg)


class FetcherTestCase(BaseTestCase):
    def test_check_custom_fetcher_called(self):
        self.client.post(reverse('start_open_id'),
                         data=DummyDjangoRequest().POST)
        self.assertTrue(MockFetcher.called)


class GetBaseURLTestCase(BaseTestCase):

    def setUp(self):
        super(GetBaseURLTestCase, self).setUp()
        self.http_consumer_url = "http://localhost/"
        self.https_consumer_url = "https://localhost/"
        self.http_proto_req = DummyRequest({'HTTP_HOST': 'localhost',
                                            'SERVER_PROTOCOL': 'HTTP/1.1'})
        self.https_proto_req = DummyRequest({'HTTP_HOST': 'localhost',
                                             'SERVER_PROTOCOL': 'HTTPS/1.1'})
        self.https_req = DummyRequest({'HTTP_HOST': 'localhost',
                                       'SERVER_PROTOCOL': 'HTTP/1.1',
                                       'HTTPS': 1})

    def test_http_consumer(self):
        url = get_base_url(self.http_proto_req)
        self.assertEqual(url, self.http_consumer_url)

    def test_https_consumer(self):
        url = get_base_url(self.https_proto_req)
        self.assertEqual(url, self.https_consumer_url)

        url = get_base_url(self.https_req)
        self.assertEqual(url, self.https_consumer_url)

    def test_consumer_on_port(self):
        req = DummyRequest({'HTTP_HOST': 'localhost',
                            'SERVER_PORT': '81',
                            'SERVER_PROTOCOL': 'HTTP/1.1'})
        base_url = 'http://localhost:81/'
        url = get_base_url(req)
        self.assertEqual(url, base_url)


class RenderIndexPageTestCase(BaseTestCase):
    def test_render_index_page_utf8(self):
        fullname = u'Dūmmẏ Ũsèṙ'.encode('utf-8')
        request = DummyRequest({
            'HTTP_HOST': 'localhost',
            'SERVER_PROTOCOL': 'HTTP/1.1'})

        template_args = {'sreg': [('fullname', fullname)],
                         'url': 'http://localhost/'}
        response = render_index_page(request, **template_args)
        headers = dict(response.items())
        self.assertEqual(headers['Content-Type'], 'text/html; charset=utf-8')
        self.assertTrue(fullname in response.content)


class ConsumerTestCase(BaseTestCase):

    def setUp(self):
        super(ConsumerTestCase, self).setUp()

        self.req = DummyDjangoRequest()
        self.endpoint = OpenIDServiceEndpoint()
        self.endpoint.claimed_id = 'oid'
        self.endpoint.server_url = 'http://localhost/'

        # make sure to enable the consumer views
        patched = patch_settings(TESTING=True)
        patched.start()
        self.addCleanup(patched.stop)

    def test_start_open_id_get(self):
        # without faking the Consumer, an openid request returns error
        r = self.client.post('/consumer/', self.req.POST, **self.req.META)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'consumer/index.html')
        self.assert_message_in_response(r, 'OpenID discovery error')

    def test_consumer_view_when_not_in_debug(self):
        with patch_settings(DEBUG=False):
            response = self.client.get(reverse('start_open_id'))
            self.assertEqual(response.status_code, 200)

    def test_consumer_view_when_not_in_testing(self):
        with patch_settings(TESTING=False):
            response = self.client.get(reverse('start_open_id'))
            self.assertEqual(response.status_code, 404)

    def test_finish_open_id_when_not_in_testing(self):
        with patch_settings(TESTING=False):
            response = self.client.get(reverse('finish_open_id'))
            self.assertEqual(response.status_code, 404)

    def test_rpXRDS_when_not_in_testing(self):
        with patch_settings(TESTING=False):
            response = self.client.get(reverse('rp_xrds'))
            self.assertEqual(response.status_code, 404)


class ConsumerFakedTestCase(ConsumerTestCase):

    def setUp(self):
        super(ConsumerFakedTestCase, self).setUp()

        class MockConsumer(consumer.Consumer):
            def begin(this, url):
                auth_request = consumer.AuthRequest(self.endpoint, None)
                return auth_request

        p = patch.object(consumer, 'Consumer', MockConsumer)
        p.start()
        self.addCleanup(p.stop)

    def test_to_regular_dict(self):
        req = DummyDjangoRequest()
        self.assertEqual(to_regular_dict(req.POST), req.POST)

    def test_start_open_id_get(self):
        r = self.client.get('/consumer/', **self.req.META)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'consumer/index.html')

    def test_start_open_id_immediate(self):
        self.req.POST.update({'mode': 'immediate'})
        r = self.client.post('/consumer/', self.req.POST, **self.req.META)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'checkid_immediate')
        self.assertEqual(query['openid.return_to'],
                         quote_plus('http://localhost/consumer/finish/'))

    def test_start_open_id_setup(self):
        self.req.POST.update({'mode': 'setup'})
        r = self.client.post('/consumer/', self.req.POST, **self.req.META)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'checkid_setup')
        self.assertEqual(query['openid.return_to'],
                         quote_plus('http://localhost/consumer/finish/'))

    def test_start_open_id_sreg(self):
        self.req.POST.update({'mode': 'setup',
                              'sreg': 'yes',
                              'sreg_fullname': SREG_REQUIRED,
                              'sreg_email': SREG_REQUIRED,
                              'sreg_nickname': SREG_OPTIONAL})
        r = self.client.post('/consumer/', self.req.POST, **self.req.META)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.sreg.required'],
                         quote_plus('fullname,email'))
        self.assertEqual(query['openid.sreg.optional'], 'nickname')

    def test_start_open_id_teams(self):
        request_teams = 'team1,team2,team3'
        self.req.POST.update({
            'mode': 'setup',
            'teams': 'yes',
            'request_teams': request_teams
        })
        r = self.client.post('/consumer/', self.req.POST, **self.req.META)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.lp.query_membership'],
                         quote_plus(request_teams))

    def test_start_open_id_should_redirect(self):
        self.req.POST['mode'] = 'setup'
        r = self.client.post('/consumer/', self.req.POST, **self.req.META)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.trust_root'],
                         quote_plus('http://localhost/consumer/'))
        self.assertEqual(query['openid.return_to'],
                         quote_plus('http://localhost/consumer/finish/'))

    def test_start_open_id_render_template(self):
        # replace consumer with OpenID 2.0 compliant one
        class MockConsumer(consumer.Consumer):
            def begin(self, url):
                endpoint = OpenIDServiceEndpoint()
                endpoint.claimed_id = 'oid'
                endpoint.server_url = 'http://localhost/'
                endpoint.type_uris = [OPENID_2_0_TYPE]
                auth_request = consumer.AuthRequest(endpoint, None)
                return auth_request
        consumer.Consumer = MockConsumer

        self.req.POST['mode'] = 'setup'
        r = self.client.post('/consumer/', self.req.POST, **self.req.META)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'consumer/request_form.html')
        self.assertTrue('openid_message'in r.context['html'])

    def test_finish_open_id_get(self):
        r = self.client.get('/consumer/finish/', **self.req.META)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'consumer/index.html')

    def test_finish_open_id_post(self):
        r = self.client.post('/consumer/finish/', **self.req.META)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'consumer/index.html')

    def test_finish_open_id_consumer_success(self):
        def mock_complete(this, request_args, return_to):
            request = {'openid.mode': 'checkid_setup',
                       'openid.trust_root': 'http://localhost/',
                       'openid.return_to': 'http://localhost/',
                       'openid.identity': IDENTIFIER_SELECT,
                       'openid.sreg.nickname': 'mynickname',
                       'openid.lp.is_member': 'myteam'}
            openid_server = server._get_openid_server()
            orequest = openid_server.decodeRequest(request)
            response = consumer.SuccessResponse(
                self.endpoint, orequest.message,
                signed_fields=['openid.sreg.nickname',
                               'openid.lp.is_member'])
            return response
        old_complete = consumer.Consumer.complete
        consumer.Consumer.complete = mock_complete

        r = self.client.post('/consumer/finish/', self.req.POST,
                             **self.req.META)
        self.assertEqual(r.context['url'], 'oid')
        self.assertEqual(r.context['sreg'], [('nickname', 'mynickname')])
        self.assertEqual(r.context['teams'], ['myteam'])

        consumer.Consumer.complete = old_complete

    def test_finish_open_id_consumer_cancel(self):

        def mock_complete(this, request_args, return_to):
            response = consumer.CancelResponse(self.endpoint)
            return response

        p = patch.object(consumer.Consumer, 'complete', mock_complete)
        p.start()
        self.addCleanup(p.stop)

        r = self.client.post('/consumer/finish/', self.req.POST,
                             **self.req.META)
        self.assert_message_in_response(r, 'OpenID authentication cancelled.')

    def test_finish_open_id_consumer_failure(self):
        def mock_complete(this, request_args, return_to):
            response = consumer.FailureResponse(self.endpoint,
                                                message='some error')
            return response
        old_complete = consumer.Consumer.complete
        consumer.Consumer.complete = mock_complete

        r = self.client.post('/consumer/finish/', self.req.POST,
                             **self.req.META)
        self.assert_message_in_response(r, 'OpenID authentication failed.')
        self.assert_message_in_response(r, 'some error')

        consumer.Consumer.complete = old_complete

    def test_rpXRDS(self):
        r = self.client.get('/consumer/xrds/', **self.req.META)
        self.assertTemplateUsed(r, 'server/openidapplication-xrds.xml')
        self.assertEqual(r['Content-Type'], YADIS_CONTENT_TYPE)

    def test_long_query_string(self):
        self.req.POST['mode'] = 'setup'
        self.req.POST['forcelongurl'] = '1'
        r = self.client.post('/consumer/', self.req.POST, **self.req.META)
        query = self.get_query(r)
        self.assertTrue(len(query['openid.return_to']) > OPENID1_URL_LIMIT)
