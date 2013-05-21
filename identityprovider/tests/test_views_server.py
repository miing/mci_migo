# -*- coding: utf-8 -*-
# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

import datetime
import urlparse

from random import randint
from urllib import quote, quote_plus

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.core.urlresolvers import reverse
from django.http import HttpRequest
from gargoyle.testutils import switches
from mock import Mock, patch
from openid.extensions.ax import (
    AXMessage,
    FetchRequest,
)
from openid.extensions.sreg import SRegRequest
from openid.message import (
    IDENTIFIER_SELECT,
    OPENID1_URL_LIMIT,
    OPENID2_NS,
    Message,
)
from openid.yadis.constants import YADIS_HEADER_NAME
from pyquery import PyQuery

import identityprovider.signed as signed
from identityprovider.const import (
    AX_DATA_FIELDS,
    AX_URI_ACCOUNT_VERIFIED,
    AX_URI_EMAIL,
    AX_URI_FULL_NAME,
    AX_URI_LANGUAGE,
)
from identityprovider.models import (
    Account,
    OpenIDAuthorization,
    OpenIDRPConfig,
    OpenIDRPSummary,
    Person,
)
from identityprovider.models.account import LPOpenIdIdentifier
from identityprovider.models.const import (
    AccountStatus,
    AccountCreationRationale,
    EmailStatus,
)
from identityprovider.models.person import PersonLocation
from identityprovider.models.authtoken import create_token
from identityprovider.views import server
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import (
    AuthenticatedTestCase,
    SSOBaseTestCase,
    authorization_header_from_token,
    patch_settings,
)
from identityprovider.utils import get_current_brand

LOCALHOST = settings.SSO_ROOT_URL.rstrip('/')


class DummyORequest(object):
    mode = 'checkid_setup'
    trust_root = LOCALHOST
    message = Message()

    def idSelect(self):
        return False


class DummySession(dict):

    @property
    def session_key(self):
        return 'abc'

    def flush(self):
        pass


class DummyRequest(object):

    def __init__(self):
        self.session = DummySession()
        self.COOKIES = {}
        self.META = {}


def delete_rpconfig_cache_entry(trust_root):
        cache.delete(OpenIDRPConfig.cache_key(trust_root))


class HandleOpenIDErrorTestCase(SSOBaseTestCase):

    # tests for the _handle_openid_error method

    def test_handle_openid_error_with_encode_url(self):
        params = {'openid.return_to': 'http://localhost/'}
        r = self.client.get(reverse('server-openid'), params)
        query = self.get_query(r)
        error_msg = 'No+mode+value+in+message+'
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'error')
        self.assertTrue(query['openid.error'].startswith(error_msg))

    def test_handle_openid_error_other(self):
        params = {'openid.mode': 'checkid_setup'}
        r = self.client.get(reverse('server-openid'), params)
        error_mode = "mode:error"
        error_msg = "error:Missing required field 'return_to'"
        self.assertEqual(r.status_code, 200)
        self.assertIn(error_mode, r.content)
        self.assertIn(error_msg, r.content)


class ProcessOpenIDRequestTestCase(SSOBaseTestCase):

    # tests for the _process_openid_request method

    def test_process_openid_request_no_orequest(self):
        r = self.client.get(reverse('server-openid'))
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'server/server_info.html')


class HandleUserResponseTestCase(SSOBaseTestCase):

    email = 'mark@example.com'
    openid_identifier = 'mark_oid'
    openid_url = settings.SSO_ROOT_URL + '+id/mark_oid'
    url = reverse('server-openid')

    def setUp(self):
        super(HandleUserResponseTestCase, self).setUp()
        # create a trusted rpconfig
        self.rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://localhost/')
        self.params = {'openid.trust_root': 'http://localhost/',
                       'openid.return_to': 'http://localhost/',
                       'openid.identity': IDENTIFIER_SELECT,
                       'openid.claimed_id': 'http://localhost/~userid',
                       'openid.ns': OPENID2_NS,
                       'openid.mode': 'checkid_setup'}
        self.account = self.factory.make_account(
            email=self.email, password=DEFAULT_USER_PASSWORD,
            openid_identifier=self.openid_identifier)

    # tests for the _handle_user_response method

    def test_handle_user_response_checkid_immediate(self):
        self.params['openid.mode'] = 'checkid_immediate'

        r = self.client.get(self.url, self.params)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'setup_needed')

    def test_handle_user_response_no_valid_openid(self):
        self.params.update({'openid.identity': 'bogus',
                            'openid.claimed_id': 'bogus'})
        r = self.client.get(self.url, self.params)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'server/invalid_identifier.html')

    def test_handle_user_response_ax_openid_is_authorized_idselect(self):
        # update rp to auto authorize
        self.rpconfig.auto_authorize = True
        self.rpconfig.allowed_user_attribs = 'fullname,email,account_verified'
        self.rpconfig.save()

        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)
        self.params.update({
            'openid.ns.ax': AXMessage.ns_uri,
            'openid.ax.mode': FetchRequest.mode,
            'openid.ax.type.fullname': AX_URI_FULL_NAME,
            'openid.ax.type.email': AX_URI_EMAIL,
            'openid.ax.type.account_verified': AX_URI_ACCOUNT_VERIFIED,
            'openid.ax.type.language': AX_URI_LANGUAGE,
            'openid.ax.required': 'fullname,email,account_verified,language',
        })
        r = self.client.get(self.url, self.params)
        query = self.get_query(r)
        self.assertEqual(query['openid.ax.value.email.1'],
                         quote_plus(self.email))
        self.assertEqual(query['openid.ax.value.fullname.1'],
                         quote_plus(self.account.get_full_name()))
        self.assertEqual(query['openid.ax.value.account_verified.1'],
                         'token_via_email')

    def test_handle_user_response_auto_auth_large_ax_sreg_response(self):
        # Make sure we get a large response
        self.account.displayname = 'a' * OPENID1_URL_LIMIT
        self.account.save()
        self._test_auto_auth(ax=['email',
                                 'account_verified',
                                 'language'],
                             sreg=['fullname'])

    def test_decide_with_ax_non_ascii_data(self):
        # Make sure we get a large response
        displayname = u'Sömê únicỏde h¢r€'
        # add padding to force a POST
        padding = u'a' * (OPENID1_URL_LIMIT - len(displayname))
        self.account.displayname = displayname + padding
        self.account.save()
        self._test_auto_auth(ax=['fullname'])

    def test_handle_user_response_auto_auth_borderline_ax_sreg_response(self):
        # Make a response that's small enough that it fits in a redirect before
        # signing, but large enough that it will need a POST after signing. We
        # might want to come up with a more robust method of determining the
        # required length, but this works for now.
        self.account.displayname = 'a' * (OPENID1_URL_LIMIT / 2)
        self.account.save()
        self._test_auto_auth(ax=['email',
                                 'account_verified',
                                 'language'],
                             sreg=['fullname'])

    def test_handle_user_response_auto_auth_large_ax_only_response(self):
        self.account.displayname = 'a' * OPENID1_URL_LIMIT
        self.account.save()
        self._test_auto_auth(ax=['fullname'])

    def test_handle_user_response_auto_auth_large_sreg_only_response(self):
        self.account.displayname = 'a' * OPENID1_URL_LIMIT
        self.account.save()
        self._test_auto_auth(sreg=['fullname'])

    def _test_auto_auth(self, ax=None, sreg=None):
        # update rp to auto authorize
        self.rpconfig.auto_authorize = True
        self.rpconfig.allowed_user_attribs = 'fullname,email,account_verified'
        self.rpconfig.save()

        # Define expected values for each attribute
        expected_values = {
            'email': self.email,
            'account_verified': 'token_via_email',
            'language': None,  # disallowed by rpconfig
            'fullname': self.account.displayname,
        }
        expected_fields = [
            ('openid.claimed_id', self.account.openid_identity_url),
            ('openid.identity', self.account.openid_identity_url),
        ]
        unexpected_fields = []

        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)
        if ax:
            self.params.update({
                'openid.ns.ax': AXMessage.ns_uri,
                'openid.ax.mode': FetchRequest.mode,
                'openid.ax.required': ','.join(ax)
            })
            self.params.update(
                [['openid.ax.type.%s' % alias,
                  AX_DATA_FIELDS.getNamespaceURI(alias)] for alias in ax])
            expected_fields += [('openid.ax.mode', 'fetch_response')]
            expected_fields += [('openid.ax.value.%s.1' % k, v)
                                for k, v in expected_values.iteritems()
                                if k in ax and v is not None]
            unexpected_fields += [('openid.ax.value.%s.1' % k)
                                  for k, v in expected_values.iteritems()
                                  if k not in ax or v is None]
        if sreg:
            self.params.update({
                'openid.ns.sreg': 'http://openid.net/sreg/1.0',
                'openid.sreg.required': ','.join(sreg),
            })
            expected_fields += [('openid.sreg.%s' % k, v)
                                for k, v in expected_values.iteritems()
                                if k in sreg and v is not None]
            unexpected_fields += ['openid.sreg.%s' % k
                                  for k, v in expected_values.iteritems()
                                  if k not in sreg or v is None]
        response = self.client.post(self.url, self.params)
        self.assertEqual('text/html', response['Content-type'].split(';')[0])
        dom = PyQuery(response.content.decode('utf-8'))
        root = dom.root.getroot()
        self.assertEqual('html', root.tag)
        body = root.find('body')
        self.assertEqual('document.forms[0].submit();', body.get('onload'))
        forms = dom.find('form')
        self.assertEqual(len(forms), 1)
        for k, v in expected_fields:
            self.assertEqual(v, forms[0].fields[k])
        for k in unexpected_fields:
            self.assertNotIn(k, forms[0].fields)
        for k in ('openid.assoc_handle', 'openid.sig'):
            self.assertIn(k, forms[0].fields)

    def test_handle_user_response_openid_is_authorized_idselect(self):
        # update rp to auto authorize
        self.rpconfig.auto_authorize = True
        self.rpconfig.save()

        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)
        r = self.client.get(self.url, self.params)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'id_res')
        self.assertEqual(query['openid.identity'],
                         quote_plus(self.account.openid_identity_url))

    def test_handle_user_response_openid_is_authorized_other_id(self):
        self.rpconfig.auto_authorize = True
        self.rpconfig.save()

        self.params['openid.identity'] = self.openid_url
        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)
        r = self.client.get(self.url, self.params)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'id_res')
        self.assertEqual(query['openid.identity'],
                         quote_plus(self.params['openid.identity']))

    def test_handle_user_response_user_is_authenticated(self):
        self.params['openid.identity'] = (settings.SSO_ROOT_URL +
                                          '+id/other_oid')
        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)
        r = self.client.get(self.url, self.params)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'cancel')

    def test_handle_user_response_decide(self):
        r = self.client.get(self.url, self.params)
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r['Location'].endswith('+decide'))

    def test_handle_user_response_with_referer(self):
        META = {'HTTP_REFERER': 'http://localhost/'}
        r = self.client.get(self.url, self.params, **META)
        openid_referer = self.client.cookies.get('openid_referer')
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r['Location'].endswith('+decide'))
        self.assertEqual(openid_referer.value, META['HTTP_REFERER'])

    def get_login_after_redirect_from_consumer(self):
        self.rpconfig.logo = 'http://someserver/logo.png'
        self.rpconfig.save()
        return self.client.get(self.url, self.params, follow=True)

    def get_new_account_after_redirect_to_login_from_consumer(self):
        r = self.get_login_after_redirect_from_consumer()
        path_parts = r.request['PATH_INFO'].split('/')
        token = path_parts[1]
        new_account_url = '/%s/+new_account' % token
        return self.client.get(new_account_url)

    def test_logo_for_rpconfig_on_decide_page(self):
        r = self.get_login_after_redirect_from_consumer()
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, '<img src="http://someserver/logo.png"/>')

    def test_logo_for_rpconfig_on_new_account_page(self):
        r = self.get_new_account_after_redirect_to_login_from_consumer()
        self.assertContains(r, '<img src="http://someserver/logo.png"/>')

    def test_rpconfig_fetch_on_new_account_page(self):
        r = self.get_new_account_after_redirect_to_login_from_consumer()
        # new account is called with a get with no rpconfig sent in
        # rpconfig should be refetched
        self.assertEqual(r.context['rpconfig'], self.rpconfig)

    def test_rpconfig_fetch_on_login_page(self):
        r = self.get_login_after_redirect_from_consumer()
        self.assertEqual(r.status_code, 200)
        path_parts = r.request['PATH_INFO'].split('/')
        token = path_parts[1]
        login_url = '/%s/+login' % token
        # leave username and password blank to cause validation error
        r = self.client.post(login_url)
        # rpconfig should be refetched
        self.assertEqual(r.context['rpconfig'], self.rpconfig)


class HandleUserResponseUnverifiedUserLogedInTestCase(SSOBaseTestCase):
    # regression tests for
    # https://bugs.launchpad.net/canonical-identity-provider/+bug/1155656
    email = 'mark@example.com'
    openid_identifier = 'mark_oid'
    openid_url = settings.SSO_ROOT_URL + '+id/mark_oid'
    url = reverse('server-openid')

    def setUp(self):
        super(HandleUserResponseUnverifiedUserLogedInTestCase, self).setUp()
        self.params = {'openid.trust_root': 'http://localhost/',
                       'openid.return_to': 'http://localhost/',
                       'openid.identity': IDENTIFIER_SELECT,
                       'openid.claimed_id': 'http://localhost/~userid',
                       'openid.ns': OPENID2_NS,
                       'openid.mode': 'checkid_setup'}
        self.account = self.factory.make_account(
            email=self.email, password=DEFAULT_USER_PASSWORD,
            openid_identifier=self.openid_identifier)
        self.account.emailaddress_set.update(status=EmailStatus.NEW)

    def assert_redirected_with_warning(self, response):
        self.assertIn(
            reverse('account-emails'), response.redirect_chain[-1][0])
        msgs = list(response.context['messages'])
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].level, server.messages.WARNING)

    def test_check_setup_with_rpconfig_when_not_allowed_unverifed(self):
        OpenIDRPConfig.objects.create(
            trust_root='http://localhost/', auto_authorize=True)
        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)

        r = self.client.get(self.url, self.params, follow=True)
        self.assert_redirected_with_warning(r)

    def test_check_setup_no_rpconfig(self):
        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)

        r = self.client.get(self.url, self.params, follow=True)
        self.assert_redirected_with_warning(r)

    def test_check_setup_with_rpconfig_when_allowed_unverifed(self):
        OpenIDRPConfig.objects.create(
            trust_root='http://localhost/',
            auto_authorize=True,
            allow_unverified=True
        )
        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)

        r = self.client.get(self.url, self.params)
        query = self.get_query(r)
        self.assertEqual(query['openid.mode'], 'id_res')
        self.assertEqual(query['openid.identity'],
                         quote_plus(self.account.openid_identity_url))

    def test_check_immediate_with_rpconfig_when_not_allowed_unverifed(self):
        OpenIDRPConfig.objects.create(
            trust_root='http://localhost/', auto_authorize=True)
        self.params['openid.mode'] = 'checkid_immediate'
        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)

        r = self.client.get(self.url, self.params)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'setup_needed')

    def test_check_immediate_no_rpconfig(self):
        self.params['openid.mode'] = 'checkid_immediate'
        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)

        r = self.client.get(self.url, self.params)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'setup_needed')

    def test_check_immediate_with_rpconfig_when_allowed_unverifed(self):
        OpenIDRPConfig.objects.create(
            trust_root='http://localhost/',
            auto_authorize=True,
            allow_unverified=True
        )

        self.params['openid.mode'] = 'checkid_immediate'
        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)
        r = self.client.get(self.url, self.params)
        query = self.get_query(r)
        self.assertEqual(query['openid.mode'], 'id_res')
        self.assertEqual(query['openid.identity'],
                         quote_plus(self.account.openid_identity_url))


class MultiLangOpenIDTestCase(SSOBaseTestCase):

    def setUp(self):
        super(MultiLangOpenIDTestCase, self).setUp()
        p = patch_settings(
            LANGUAGE_CODE='en',
            SUPPORTED_LANGUAGES=['en', 'de'],
        )
        p.start()
        self.addCleanup(p.stop)

    def flag_icon(self, lang):
        tag = '<img src="/assets/identityprovider/flags/%s.png" alt="%s" />'
        return tag % (lang, lang)

    def test_no_lang_specified(self):
        response = self.client.get(reverse('server-openid'))
        expected = "This is {0}, built on OpenID".format(
            settings.BRAND_DESCRIPTIONS.get(get_current_brand()))
        self.assertContains(response, expected)
        self.assertEqual('en', self.client.session['django_language'])

    def test_german(self):
        response = self.client.get(reverse('server-openid',
                                           kwargs=dict(lang='de')))
        self.assertContains(response, self.flag_icon('de'))
        self.assertEqual('de', self.client.session['django_language'])

    def test_german_with_country_code(self):
        # This should default back to 'de'.
        response = self.client.get(reverse('server-openid',
                                           kwargs=dict(lang='de_CH')))
        self.assertContains(response, self.flag_icon('de'))
        self.assertEqual('de', self.client.session['django_language'])

    def test_unsupported_language(self):
        response = self.client.get(reverse('server-openid',
                                           kwargs=dict(lang='sw')))
        self.assertContains(response, self.flag_icon('en'))
        self.assertEqual('en', self.client.session['django_language'])

    def test_language_persists_in_session(self):
        self.client.get(reverse('server-openid', kwargs=dict(lang='de')))
        self.assertEqual('de', self.client.session['django_language'])
        # Requesting a second time will still bring back German
        # if no other setting takes precedence (like the user's preference)
        self.client.get(reverse('server-openid'))
        self.assertEqual('de', self.client.session['django_language'])


class ValidOpenIDTestCase(SSOBaseTestCase):

    def test_is_valid_openid_idselect(self):
        valid = server._is_valid_openid_for_this_site(IDENTIFIER_SELECT)
        self.assertTrue(valid)

    def test_is_valid_openid_different_scheme(self):
        srvparts = urlparse.urlparse(settings.SSO_ROOT_URL)
        if srvparts.scheme == 'http':
            scheme = 'https'
        else:
            scheme = 'http'
        identity = settings.SSO_ROOT_URL.replace(srvparts.scheme, scheme)
        valid = server._is_valid_openid_for_this_site(identity)
        self.assertFalse(valid)

    def test_is_valid_openid_different_port(self):
        srvparts = urlparse.urlparse(settings.SSO_ROOT_URL)
        if srvparts.port is not None:
            port = int(srvparts.port) + 1
        else:
            port = 81
        identity = "%s:%s//%s%s" % (srvparts.scheme, port,
                                    srvparts.hostname, srvparts.path)
        valid = server._is_valid_openid_for_this_site(identity)
        self.assertFalse(valid)

    def test_is_valid_openid_different_hostname(self):
        identity = 'http://testserver/'
        valid = server._is_valid_openid_for_this_site(identity)
        self.assertFalse(valid)

    def test_is_valid_openid_path_patterns(self):
        identity = settings.SSO_ROOT_URL
        valid = server._is_valid_openid_for_this_site(identity)
        self.assertTrue(valid)

        identity += '+id/foo'
        valid = server._is_valid_openid_for_this_site(identity)
        self.assertTrue(valid)

        identity = settings.SSO_ROOT_URL + '~foo'
        valid = server._is_valid_openid_for_this_site(identity)
        self.assertTrue(valid)

        # try a non-normalized uri
        identity = settings.SSO_ROOT_URL.strip('/')
        valid = server._is_valid_openid_for_this_site(identity)
        self.assertTrue(valid)

    def test_is_valid_openid_other(self):
        identity = settings.SSO_ROOT_URL + '+foo'
        valid = server._is_valid_openid_for_this_site(identity)
        self.assertFalse(valid)

    def test_is_valid_openid_error(self):
        valid = server._is_valid_openid_for_this_site(None)
        self.assertFalse(valid)


class DecideBaseTestCase(AuthenticatedTestCase):

    def setUp(self):
        super(DecideBaseTestCase, self).setUp()
        self._apply_patch('webui.decorators.disable_cookie_check')
        self._prepare_openid_token()

    @property
    def url(self):
        return reverse('server-decide', kwargs=dict(token=self.token))

    def _prepare_openid_token(self, param_overrides=None):
        request = {'openid.mode': 'checkid_setup',
                   'openid.trust_root': 'http://localhost/',
                   'openid.return_to': 'http://localhost/',
                   'openid.identity': IDENTIFIER_SELECT}
        if param_overrides:
            request.update(param_overrides)
        openid_server = server._get_openid_server()
        self.orequest = openid_server.decodeRequest(request)
        self.token = create_token(16)
        session = self.client.session
        session[self.token] = signed.dumps(self.orequest, settings.SECRET_KEY)
        session.save()


class DecideTestCase(DecideBaseTestCase):

    def test_decide_invalid(self):
        self.token = 'a' * 16
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, 'Invalid OpenID transaction')

    def test_decide_authenticated(self):
        r = self.client.post(self.url, {'ok': 'ok'})
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'id_res')

    def test_decide_authenticated_with_post(self):
        # Using a return-to URL that is more than OPENID1_URL_LIMIT
        # characters long will force the assertion to be sent as a
        # POSTing form (instead of a 302 redirect).
        return_to = 'http://localhost/' + (OPENID1_URL_LIMIT * 'a')
        self._prepare_openid_token({
            'openid.return_to': return_to,
            'openid.ns': OPENID2_NS,
            'openid.claimed_id': 'http://localhost/~userid'})
        r = self.client.post(self.url, {'ok': ''})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r['Content-Type'], 'text/html')
        self.assertContains(r, '<form ')
        self.assertContains(r, return_to)

    def test_decide_auto_authorize(self):
        # make sure rpconfig is set to auto authorize
        OpenIDRPConfig.objects.create(
            trust_root='http://localhost/', auto_authorize=True)
        r = self.client.post(self.url)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'id_res')

    def test_decide_process(self):
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'server/decide.html')

    def test_decide_includes_rp_analytics(self):
        OpenIDRPConfig.objects.create(
            trust_root='http://localhost/',
            ga_snippet='[["_setAccount", "12345"]]')
        r = self.client.get(self.url)

        self.assertContains(r, "_gaq.push(['_setAccount', '12345']);")

    def test_decide_not_authenticated(self):
        self.client.logout()

        # create a trusted rpconfig
        OpenIDRPConfig.objects.create(trust_root='http://localhost/')

        # start openid request
        params = {'openid.trust_root': 'http://localhost/',
                  'openid.return_to': 'http://localhost/',
                  'openid.identity': IDENTIFIER_SELECT,
                  'openid.claimed_id': 'http://localhost/~userid',
                  'openid.ns': OPENID2_NS,
                  'openid.mode': 'checkid_setup'}
        r = self.client.get(reverse('server-openid'), params)
        # follow redirect
        path = r['Location'].split('http://testserver')[1]
        self.assertTrue(path.endswith('+decide'))
        r = self.client.get(path)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'registration/login.html')

    def test_decide_multiple_openidrpsummary(self):
        # create multiple matching OpenIDRPSummary objects
        trust_root = 'http://localhost/'
        delete_rpconfig_cache_entry(trust_root)

        OpenIDRPSummary.objects.create(
            account=self.account, trust_root=trust_root,
            openid_identifier='http://localhost/~openid1')
        OpenIDRPSummary.objects.create(
            account=self.account, trust_root=trust_root,
            openid_identifier='http://otherhost/~openid1')

        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'server/decide.html')

    def test_decide_team_membership_with_auto_authorize(self):
        # make sure rpconfig is set to auto authorize
        team_name = 'ubuntu-team'
        team = self.factory.make_team(name=team_name)
        self.factory.add_account_to_team(self.account, team)

        OpenIDRPConfig.objects.create(
            trust_root='http://localhost/', auto_authorize=True)

        param_overrides = {
            'openid.lp.query_membership': team_name,
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        r = self.client.post(self.url)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'id_res')
        self.assertEqual(query['openid.lp.is_member'], team_name)

    def test_yui_js_url(self):
        r = self.client.get(self.url)
        self.assertContains(
            r, '{0}identityprovider/lazr-js/yui/yui-min.js'.format(
                settings.STATIC_URL))

    def test_check_team_membership_multiple_openidrpsummary(self):
        # create multiple matching OpenIDRPSummary objects
        trust_root = 'http://localhost/'
        OpenIDRPSummary.objects.create(
            account=self.account, trust_root=trust_root,
            openid_identifier='http://localhost/~openid1')
        OpenIDRPSummary.objects.create(
            account=self.account, trust_root=trust_root,
            openid_identifier='http://otherhost/~openid1')

        request = Mock()
        request.user = self.account
        oresponse = Mock()
        # _check_team_membership should not raise an error
        # no extra check is needed
        server._check_team_membership(request, self.orequest, oresponse)

    def test_ax_and_sreg_fields_are_merged(self):
        """If both SReg and AX requests are present, only display one set of
        fields."""
        team_name = 'ubuntu-team'
        team = self.factory.make_team(name=team_name)
        self.factory.add_account_to_team(self.account, team)

        # create a trusted rpconfig
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            allowed_user_attribs='fullname,email,account_verified',
            can_query_any_team=True,
            description="Some description",
        )
        rpconfig.save()
        param_overrides = {
            'openid.sreg.required': 'nickname,email,fullname,language',
            'openid.ns.ax': AXMessage.ns_uri,
            'openid.ax.mode': FetchRequest.mode,
            'openid.ax.type.fullname': AX_URI_FULL_NAME,
            'openid.ax.type.email': AX_URI_EMAIL,
            'openid.ax.type.account_verified': AX_URI_ACCOUNT_VERIFIED,
            'openid.ax.type.language': AX_URI_LANGUAGE,
            'openid.ax.required': 'fullname,email,account_verified,language',
            'openid.lp.query_membership': team_name,
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        response = self.client.get('/%s/+decide' % self.token)
        dom = PyQuery(response.content)
        # Only 3 fields, because language isn't allowed by the rpconfig
        self.assertEqual(len(dom.find('li.user_attribs')), 3)

    def test_list_of_details_is_complete_with_sreg(self):
        team_name = 'ubuntu-team'
        team = self.factory.make_team(name=team_name)
        self.factory.add_account_to_team(self.account, team)

        # create a trusted rpconfig
        OpenIDRPConfig.objects.create(
            trust_root='http://localhost/',
            allowed_user_attribs='fullname,email,language',
            can_query_any_team=True,
            description="Some description",
        )
        param_overrides = {
            'openid.sreg.required': 'nickname,email,fullname,language',
            'openid.lp.query_membership': team_name,
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        response = self.client.get(self.url)
        self.assertContains(response, "Team membership")
        self.assertContains(response, "Full name")
        self.assertContains(response, "Email address")
        self.assertContains(response, "Preferred language")

    def test_list_of_details_is_complete_with_ax(self):
        team_name = 'ubuntu-team'
        team = self.factory.make_team(name=team_name)
        self.factory.add_account_to_team(self.account, team)

        # create a trusted rpconfig
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            allowed_user_attribs='fullname,email,account_verified',
            can_query_any_team=True,
            description="Some description",
        )
        rpconfig.save()
        param_overrides = {
            'openid.ns.ax': AXMessage.ns_uri,
            'openid.ax.mode': FetchRequest.mode,
            'openid.ax.type.fullname': AX_URI_FULL_NAME,
            'openid.ax.type.email': AX_URI_EMAIL,
            'openid.ax.type.account_verified': AX_URI_ACCOUNT_VERIFIED,
            'openid.ax.type.language': AX_URI_LANGUAGE,
            'openid.ax.required': 'fullname,email,account_verified,language',
            'openid.lp.query_membership': team_name,
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        response = self.client.get('/%s/+decide' % self.token)
        self.assertContains(response, "Team membership")
        self.assertContains(response, "Full name")
        self.assertContains(response, "Email address")
        self.assertContains(response, "Account verified")

    def _test_state_of_checkboxes_and_data_formats(
            self, dom, field, label=None, value=None, required=False,
            disabled=False, checked=False):
        elem = dom.find('#id_%s' % field)
        self.assertEqual(len(elem), 1)
        self.assertEqual(elem[0].get('type'), 'checkbox')
        if required:
            self.assertEqual(elem[0].get('class'), 'required')
        else:
            self.assertIsNone(elem[0].get('class'))
        if checked:
            self.assertEqual(elem[0].get('checked'), 'checked')
        else:
            self.assertIsNone(elem[0].get('checked'))
        if disabled:
            self.assertEqual(elem[0].get('disabled'), 'disabled')
        else:
            self.assertIsNone(elem[0].get('disabled'))
        elem = dom.find('label[for=id_%s]' % field)
        self.assertEqual(len(elem), 1)
        self.assertEqual(
            elem[0].text, '%s: %s' % (label, value) if label else value)

    def _test_required_trusted_field(self, dom, field, label=None, value=None):
        """Required fields for trusted RPs *should* be checked, *should* be
        disabled and *should* be required."""
        self._test_state_of_checkboxes_and_data_formats(
            dom, field=field, label=label, value=value,
            required=True, disabled=True, checked=True)

    def _test_optional_trusted_field(self, dom, field, label=None, value=None):
        """Optional fields for trusted RPs *should* be checked, *should not* be
        disabled and *should not* be required."""
        self._test_state_of_checkboxes_and_data_formats(
            dom, field=field, label=label, value=value, checked=True,
            disabled=False, required=False)

    def _test_required_untrusted_field(self, dom, field, label=None,
                                       value=None):
        """Required fields for untrusted RPs *should* be checked, *should not*
        be disabled and *should* be required."""
        self._test_state_of_checkboxes_and_data_formats(
            dom, field=field, label=label, value=value, checked=True,
            disabled=False, required=True)

    def _test_optional_untrusted_field(self, dom, field, label=None,
                                       value=None):
        """Optional fields for untrusted RPs *should not* be checked,
        *should not* be disabled and *should not* be required."""
        self._test_state_of_checkboxes_and_data_formats(
            dom, field=field, label=label, value=value, required=False,
            checked=False, disabled=False)

    def test_state_of_checkboxes_and_data_formats_trusted_sreg(self):
        teams = ('ubuntu-team', 'launchpad-team', 'isd-team')
        for team_name in teams:
            team = self.factory.make_team(name=team_name)
            self.factory.add_account_to_team(self.account, team)

        # create a trusted rpconfig
        OpenIDRPConfig.objects.create(
            trust_root='http://localhost/',
            allowed_user_attribs='nickname,email,language',
            can_query_any_team=True,
            description="Some description",
        )
        param_overrides = {
            'openid.sreg.required': 'nickname,email,fullname',
            'openid.sreg.optional': 'language',
            'openid.lp.query_membership': ','.join(teams),
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        response = self.client.get(self.url)
        dom = PyQuery(response.content)
        self.assertEqual(len(dom.find('li.user_attribs')), 3)

        nickname = self.account.person.name
        self._test_required_trusted_field(dom, field='nickname',
                                          label='Username', value=nickname)
        self._test_required_trusted_field(dom, field='email',
                                          label='Email address',
                                          value=self.login_email)

        self._test_optional_trusted_field(dom, field='language',
                                          label='Preferred language',
                                          value='en')

        for team in teams:
            self._test_optional_trusted_field(dom, field=team, value=team)

    def test_state_of_checkboxes_and_data_formats_trusted_ax(self):
        teams = ('ubuntu-team', 'launchpad-team', 'isd-team')
        for team_name in teams:
            team = self.factory.make_team(name=team_name)
            self.factory.add_account_to_team(self.account, team)

        # create a trusted rpconfig
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            allowed_user_attribs='nickname,email,language,account_verified',
            can_query_any_team=True,
            description="Some description",
        )
        rpconfig.save()
        param_overrides = {
            'openid.ns.ax': AXMessage.ns_uri,
            'openid.ax.mode': FetchRequest.mode,
            'openid.ax.type.fullname': AX_URI_FULL_NAME,
            'openid.ax.type.email': AX_URI_EMAIL,
            'openid.ax.type.account_verified': AX_URI_ACCOUNT_VERIFIED,
            'openid.ax.type.language': AX_URI_LANGUAGE,
            'openid.ax.required': 'fullname,email,account_verified',
            'openid.ax.if_available': 'language',
            'openid.lp.query_membership': ','.join(teams),
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        response = self.client.get('/%s/+decide' % self.token)
        dom = PyQuery(response.content)
        self.assertEqual(len(dom.find('li.user_attribs')), 3)

        self._test_required_trusted_field(dom, field='email',
                                          label='Email address',
                                          value=self.login_email)
        self._test_required_trusted_field(dom, field='account_verified',
                                          label='Account verified',
                                          value='token_via_email')

        self._test_optional_trusted_field(dom, field='language',
                                          label='Preferred language',
                                          value='en')

        for team in teams:
            self._test_optional_trusted_field(dom, field=team, value=team)

    def test_state_of_checkboxes_and_data_formats_untrusted_sreg(self):
        team_name = 'ubuntu-team'
        team = self.factory.make_team(name=team_name)
        self.factory.add_account_to_team(self.account, team)

        # create a trusted rpconfig
        OpenIDRPConfig.objects.create(
            trust_root='http://untrusted/',
            can_query_any_team=True,
            description="Some description",
        )
        param_overrides = {
            'openid.sreg.required': 'nickname,email,fullname',
            'openid.sreg.optional': 'language',
            'openid.lp.query_membership': 'ubuntu-team',
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        response = self.client.get(self.url)
        dom = PyQuery(response.content)
        self.assertEqual(len(dom.find('li.user_attribs')), 4)

        nickname = self.account.person.name
        self._test_required_untrusted_field(dom, field='nickname',
                                            label='Username', value=nickname)
        self._test_required_untrusted_field(dom, field='email',
                                            label='Email address',
                                            value=self.login_email)

        self._test_optional_untrusted_field(dom, field='language',
                                            label='Preferred language',
                                            value='en')

        self._test_optional_untrusted_field(dom, field=team_name,
                                            label='Team membership',
                                            value=team_name)

    def test_state_of_checkboxes_and_data_formats_untrusted_ax(self):
        team_name = 'ubuntu-team'
        team = self.factory.make_team(name=team_name)
        self.factory.add_account_to_team(self.account, team)

        # create a trusted rpconfig
        trust_root = 'http://untrusted/'
        rpconfig = OpenIDRPConfig(
            trust_root=trust_root,
            can_query_any_team=True,
            description="Some description",
        )

        delete_rpconfig_cache_entry("http://localhost/")

        rpconfig.save()
        param_overrides = {
            'openid.ns.ax': AXMessage.ns_uri,
            'openid.ax.mode': FetchRequest.mode,
            'openid.ax.type.fullname': AX_URI_FULL_NAME,
            'openid.ax.type.email': AX_URI_EMAIL,
            'openid.ax.type.account_verified': AX_URI_ACCOUNT_VERIFIED,
            'openid.ax.type.language': AX_URI_LANGUAGE,
            'openid.ax.required': 'fullname,email,account_verified',
            'openid.ax.if_available': 'language',
            'openid.lp.query_membership': 'ubuntu-team',
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        response = self.client.get('/%s/+decide' % self.token)
        dom = PyQuery(response.content)
        self.assertEqual(len(dom.find('li.user_attribs')), 4)

        fullname = self.account.get_full_name()
        self._test_required_untrusted_field(dom, field='fullname',
                                            label='Full name',
                                            value=fullname)
        self._test_required_untrusted_field(dom, field='email',
                                            label='Email address',
                                            value=self.login_email)

        self._test_optional_untrusted_field(dom, field='language',
                                            label='Preferred language',
                                            value='en')

        self._test_optional_untrusted_field(dom, field=team_name,
                                            label='Team membership',
                                            value=team_name)


class DecideUserUnverifiedTestCase(DecideBaseTestCase):

    def setUp(self):
        super(DecideUserUnverifiedTestCase, self).setUp()
        self.account.emailaddress_set.update(status=EmailStatus.NEW)
        assert not self.account.is_verified

    def assert_redirected_with_warning(self, response, name):
        self.assertIn(reverse('account-emails'), response.redirect_chain[0][0])
        msgs = list(response.context['messages'])
        self.assertEqual(len(msgs), 1)
        msg = server.SITE_REQUIRES_VERIFIED.format(rp_name=name)
        self.assertEqual(msgs[0].message, msg)
        self.assertEqual(msgs[0].level, server.messages.WARNING)

    def assert_decide_page_shown(self, response):
        tree = PyQuery(response.content)
        trust_root = tree.find('div#trust-root')
        self.assertEqual(len(trust_root), 1)
        trust_root = trust_root[0]
        self.assertEqual(trust_root[0].text.strip(), 'You are logging in to')

        link = trust_root.getchildren()[0].find('a')
        self.assertEqual(link.get('href'), 'http://localhost/')

        button = tree.find('button[type="submit"][name="yes"]')
        self.assertEqual(len(button), 1)
        button = button[0]
        self.assertEqual(button.text_content(), 'Yes, log me in')

    def test_user_unverified_no_rpconfig(self):
        assert OpenIDRPConfig.objects.count() == 0
        response = self.client.get(self.url, follow=True)
        self.assert_redirected_with_warning(response, 'http://localhost/')

    def test_user_unverified_rpconfig_allow_unverified(self):
        OpenIDRPConfig.objects.create(
            trust_root='http://localhost/', allow_unverified=True)
        self._prepare_openid_token()
        response = self.client.get(self.url, follow=True)
        self.assert_decide_page_shown(response)

    def test_user_unverified_rpconfig_does_not_allow_unverified(self):
        rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://localhost/', allow_unverified=False,
            displayname='Foo Bar baz')
        self._prepare_openid_token()
        response = self.client.get(self.url, follow=True)
        self.assert_redirected_with_warning(response, rpconfig.displayname)


# The particular flows in these test cases are not particularly
# important.  The important detail is that a 2nd factor be asked of
# the user if two-factor security has been requested by any party.
class Decide2FTestCase(SSOBaseTestCase):

    fixtures = ['2f', 'twofactor']

    def setUp(self):
        super(Decide2FTestCase, self).setUp()

        self.account = Account.objects.filter()[0]
        self.rpconfig = OpenIDRPConfig.objects.filter()[0]
        self.rpconfig.trust_root = LOCALHOST + '/consumer'
        self.rpconfig.save()
        patcher = patch('webui.decorators.disable_cookie_check')
        patcher.start()
        self.addCleanup(patcher.stop)

    def _user_requires_2f(self):
        self.account.twofactor_required = True
        self.account.save()

    def _site_requires_2f(self):
        self.rpconfig.require_two_factor = True
        self.rpconfig.save()

    def _login_1_factor(self):
        self.client.login(username='isdtest@canonical.com',
                          password='Admin007')

    def _login_2_factor(self):
        self._login_1_factor()
        self.client.post(reverse('twofactor'), {'oath_token': 287082})

    def _start_transaction(self):
        data = {
            'openid.mode': 'checkid_setup',
            'openid.identity': LOCALHOST + '/+id/KxHA3MH',
            'openid.return_to': LOCALHOST + '/consumer'
        }
        r = self.client.get(reverse('server-openid'), data)
        rp_token = r['Location'].split('/')[3]
        decide_path = '/' + '/'.join(r['Location'].split('/')[3:])
        return rp_token, decide_path

    def test_user_unauthed(self):
        self._user_requires_2f()

        rp_token, decide_path = self._start_transaction()

        # We should be asked to log in
        r = self.client.get(decide_path)
        self.assertTemplateUsed(r, 'registration/login.html')
        login_path = r.context['login_path']

        # After submitting username and password, we should be asked
        # for 2-f
        data = {
            'email': 'isdtest@canonical.com',
            'password': 'Admin007',
        }
        r = self.client.post(login_path, data, follow=True)
        twof_path = reverse('twofactor', args=[rp_token])
        self.assertRedirects(r, twof_path)
        self.assertTemplateUsed(r, 'registration/twofactor.html')

        # After submitting an OTP, we should be allowed to authorize
        # the RP
        r = self.client.post(twof_path, {'oath_token': '287082'}, follow=True)
        self.assertRedirects(r, decide_path)
        self.assertTemplateUsed(r, 'server/decide.html')

        # Doing so should take us to the RP
        r = self.client.post(decide_path, {'ok': ''})
        self.assertTrue(r['Location'].startswith(
            LOCALHOST + '/consumer'))

    def test_user_1st_factored(self):
        '''This test assumes that SSO allows you to "log in" with only
        an email and password without doing a 2-f session upgrade,
        even if it subsequently blocks acccess to everything.  If SSO
        is changed to not log in the user in this case, this test
        should disappear.'''

        self._user_requires_2f()

        self._login_1_factor()

        rp_token, decide_path = self._start_transaction()

        # We should be asked for 2-f
        r = self.client.get(decide_path, follow=True)
        twof_path = reverse('twofactor', args=[rp_token])
        self.assertRedirects(r, twof_path)
        self.assertTemplateUsed(r, 'registration/twofactor.html')

        # After submitting an OTP, we should be allowed to authorize
        # the RP
        r = self.client.post(
            twof_path, {'oath_token': '287082', 'next': decide_path},
            follow=True,
        )
        self.assertRedirects(r, decide_path)
        self.assertTemplateUsed(r, 'server/decide.html')

        # Doing so should take us to the RP
        r = self.client.post(decide_path, {'ok': ''})
        self.assertTrue(r['Location'].startswith(
            LOCALHOST + '/consumer'))

    def test_user_2nd_factored(self):
        self._user_requires_2f()

        self._login_2_factor()

        rp_token, decide_path = self._start_transaction()

        # We should be allowed to authorize the RP
        r = self.client.get(decide_path)
        self.assertTemplateUsed(r, 'server/decide.html')

        # Doing so should take us to the RP
        r = self.client.post(decide_path, {'ok': ''})
        self.assertTrue(r['Location'].startswith(
            LOCALHOST + '/consumer'))

    def test_site_unauthed(self):
        self._site_requires_2f()

        rp_token, decide_path = self._start_transaction()

        # We should be asked to log in, including 2-f
        r = self.client.get(decide_path)
        self.assertTemplateUsed(r, 'registration/login.html')
        login_path = r.context['login_path']

        # After submitting username, password, and OTP, we should be
        # allowed to authorize the RP
        data = {
            'email': 'isdtest@canonical.com',
            'password': 'Admin007',
            'oath_token': '287082',
        }
        r = self.client.post(login_path, data, follow=True)
        self.assertRedirects(r, decide_path)
        self.assertTemplateUsed(r, 'server/decide.html')

        # Doing so should take us to the RP
        r = self.client.post(decide_path, {'ok': ''})
        self.assertTrue(r['Location'].startswith(
            LOCALHOST + '/consumer'))

    def test_site_1st_factored(self):
        '''This test assumes that SSO allows you to "log in" with only
        an email and password without doing a 2-f session upgrade,
        even if it subsequently blocks acccess to everything.  If SSO
        is changed to not log in the user in this case, this test
        should disappear.'''

        self._site_requires_2f()

        self._login_1_factor()

        rp_token, decide_path = self._start_transaction()

        # We should be asked for 2-f
        r = self.client.get(decide_path, follow=True)
        twof_path = reverse('twofactor', args=[rp_token])
        self.assertRedirects(r, twof_path)
        self.assertTemplateUsed(r, 'registration/twofactor.html')

        # After submitting an OTP, we should be allowed to authorize
        # the RP
        r = self.client.post(twof_path, {'oath_token': '287082'}, follow=True)
        self.assertRedirects(r, decide_path)
        self.assertTemplateUsed(r, 'server/decide.html')

        # Doing so should take us to the RP
        r = self.client.post(decide_path, {'ok': ''})
        self.assertTrue(r['Location'].startswith(
            LOCALHOST + '/consumer'))

    def test_site_2nd_factored(self):
        self._site_requires_2f()

        self._login_2_factor()

        rp_token, decide_path = self._start_transaction()

        # We should be allowed to authorize the RP
        r = self.client.get(decide_path)
        self.assertTemplateUsed(r, 'server/decide.html')

        # Doing so should take us to the RP
        r = self.client.post(decide_path, {'ok': ''})
        self.assertTrue(r['Location'].startswith(
            LOCALHOST + '/consumer'))

    def test_2f_circumvention(self):
        '''This test assumes that SSO allows you to "log in" with only
        an email and password without doing a 2-f session upgrade,
        even if it subsequently blocks acccess to everything.  If SSO
        is changed to not log in the user in this case, this test
        should disappear.'''

        # An RP set for auto-authorization is the most aggresive about
        # letting the user through, so we test against that.
        self.rpconfig.auto_authorize = True
        self.rpconfig.save()
        self._user_requires_2f()

        self._login_1_factor()

        rp_token, decide_path = self._start_transaction()

        # We should be asked for 2-f
        r = self.client.get(decide_path)
        twof_path = reverse('twofactor', args=[rp_token])
        self.assertRedirects(r, twof_path)

    @switches(TWOFACTOR=False)
    def test_site_requires_2f_but_feature_disabled(self):
        # make sure user is allowed to login to a site which requires
        # twofactor, if the feature is disabled
        self.rpconfig.require_two_factor = True
        self.rpconfig.save()

        self._login_1_factor()

        rp_token, decide_path = self._start_transaction()
        response = self.client.get(decide_path)
        self.assertEqual(response.status_code, 200)


class PreAuthorizeTestCase(AuthenticatedTestCase):

    def setUp(self):
        super(PreAuthorizeTestCase, self).setUp()
        self._apply_patch('webui.decorators.disable_cookie_check')
        p = patch_settings(OPENID_PREAUTHORIZATION_ACL=[
            ('http://localhost/', 'http://localhost/')
        ])
        p.start()
        self.addCleanup(p.stop)

        OpenIDRPConfig.objects.create(trust_root='http://localhost/')

    def test_pre_authorize_get(self):
        r = self.client.get('/+pre-authorize-rp')
        self.assertEqual(r.status_code, 400)

    def test_pre_authorize_unauthorized(self):
        r = self.client.post('/+pre-authorize-rp',
                             {'trust_root': 'http://localhost/',
                              'callback': 'http://localhost/'})
        self.assertEqual(r.status_code, 400)

    def test_pre_authorize_no_pre_authorized(self):
        p = patch_settings(OPENID_PREAUTHORIZATION_ACL=[])
        p.start()
        self.addCleanup(p.stop)

        extra = {'HTTP_REFERER': 'http://localhost/'}
        r = self.client.post('/+pre-authorize-rp',
                             {'trust_root': 'http://localhost/',
                              'callback': 'http://localhost/'},
                             **extra)
        self.assertEqual(r.status_code, 400)

    def test_pre_authorize_authenticated(self):
        extra = {'HTTP_REFERER': 'http://localhost/'}
        r = self.client.post('/+pre-authorize-rp',
                             {'trust_root': 'http://localhost/',
                              'callback': 'http://localhost/'},
                             **extra)
        self.assertRedirects(r, 'http://localhost/')

    def test_pre_authorize_not_authenticated(self):
        self.client.logout()
        extra = {'HTTP_REFERER': 'http://localhost/'}
        r = self.client.post('/+pre-authorize-rp',
                             {'trust_root': 'http://localhost/',
                              'callback': 'http://localhost/'},
                             **extra)
        next_url = '/+login?next=' + quote('/+pre-authorize-rp?')
        self.assertRedirects(r, next_url)

    def test_pre_authorize_after_login(self):
        # make sure we are logged out
        self.client.logout()

        # attempt to pre-authorize
        extra = {'HTTP_REFERER': 'http://localhost/'}
        data = {'trust_root': 'http://localhost/',
                'callback': 'http://localhost/'}
        r = self.client.post('/+pre-authorize-rp', data, **extra)
        # we get redirected to login
        next_url = '/+login?next=' + quote('/+pre-authorize-rp?')
        self.assertRedirects(r, next_url)
        # and the referer info is stored in the session
        self.assertEqual(self.client.session['pre_auth_referer'],
                         'http://localhost/')
        self.assertTrue(self.client.session['pre_auth_referer_for'],
                        'http://localhost/')

        # login and redirect to pre-authorize again
        data.update({'email': self.login_email,
                     'password': self.login_password,
                     'next': '/+pre-authorize-rp'})
        r = self.client.post('/+login', data, **extra)
        r = self.client.post('/+pre-authorize-rp', data, **extra)
        # we get effectively pre-authorized
        self.assertRedirects(r, 'http://localhost/')
        # and the pre-auth session data gets removed
        self.assertNotIn('pre_auth_referer', self.client.session)
        self.assertNotIn('pre_auth_referer_for', self.client.session)

    def test_pre_authorize_sees_referer_not_trust_root(self):
        p = patch_settings(OPENID_PREAUTHORIZATION_ACL=[
            ('http://otherhost/', 'http://localhost/')
        ])
        p.start()
        self.addCleanup(p.stop)

        # make sure we are logged out
        self.client.logout()

        # attempt to pre-authorize
        extra = {'HTTP_REFERER': 'http://otherhost/'}
        data = {'trust_root': 'http://localhost/',
                'callback': 'http://localhost/'}
        r = self.client.post('/+pre-authorize-rp', data, **extra)
        # we get redirected to login
        next_url = '/+login?next=' + quote('/+pre-authorize-rp?')
        self.assertRedirects(r, next_url)
        # and the referer info is stored in the session
        self.assertEqual(self.client.session['pre_auth_referer'],
                         'http://otherhost/')
        self.assertTrue(self.client.session['pre_auth_referer_for'],
                        'http://localhost/')

        # attempt to pre-authorize for a different trust_root
        data['trust_root'] = 'http://otherhost/'
        r = self.client.post('/+pre-authorize-rp', data, **extra)
        # pre-authorization is denied
        self.assertEqual(r.status_code, 400)


class CancelTestCase(AuthenticatedTestCase):

    def setUp(self):
        super(CancelTestCase, self).setUp()

        self.params = request = {'openid.mode': 'checkid_setup',
                                 'openid.trust_root': 'http://localhost/',
                                 'openid.return_to': 'http://localhost/',
                                 'openid.identity': IDENTIFIER_SELECT}
        openid_server = server._get_openid_server()
        self.orequest = openid_server.decodeRequest(request)
        self.token = create_token(16)
        session = self.client.session
        session[self.token] = signed.dumps(self.orequest, settings.SECRET_KEY)
        session.save()

        OpenIDRPConfig.objects.create(trust_root='http://localhost')

    def test_cancel_invalid_openid_transaction(self):
        token = 'a' * 16
        r = self.client.get("/%s/+cancel" % token)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, 'Invalid OpenID transaction')

    def test_cancel_user_is_authenticated(self):
        # cancel request
        r = self.client.get("/%s/+cancel" % self.token)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'cancel')

    def test_cancel_user_is_not_authenticated(self):
        # save session data
        session_data = self.client.session[self.token]

        # logout
        self.client.logout()
        # request something so we get a real session in the client
        self.client.get(reverse('server-openid'), self.params)

        # manipulate session
        session = self.client.session
        session[self.token] = session_data
        session.save()

        # cancel request
        r = self.client.get("/%s/+cancel" % self.token)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'cancel')


class XRDSTestCase(SSOBaseTestCase):

    def assert_xrds_document(self, response, template=None):
        if template is None:
            template = 'openidapplication-xrds.xml'
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/xrds+xml')
        self.assertTemplateUsed(response, 'server/' + template)

    def test_xrds(self):
        r = self.client.get('/+xrds')
        self.assert_xrds_document(r)

    def test_root_page_also_returns_xrds_document_when_right_header_is_used(
            self):
        r = self.client.get('/', HTTP_ACCEPT="application/xrds+xml")
        self.assert_xrds_document(r)

    def test_identity_page_nonexisting_account(self):
        r = self.client.get('/+id/aaaaaaaaaaaaaaaa')
        self.assertEqual(r.status_code, 404)

    def test_identity_page_inactive_account(self):
        account = self.factory.make_account(status=AccountStatus.DEACTIVATED)
        r = self.client.get("/+id/%s" % account.openid_identifier)
        self.assertEqual(r.status_code, 404)

    def test_identity_page_active_account(self):
        account = self.factory.make_account()
        r = self.client.get("/+id/%s" % account.openid_identifier)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'server/person.html')
        self.assertEqual(r[YADIS_HEADER_NAME],
                         "%s/+xrds" % account.openid_identity_url)

    def test_xrds_identity_page_nonexisting_account(self):
        r = self.client.get('/+id/aaaaaaaaaaaaaaaa')
        self.assertEqual(r.status_code, 404)

    def test_xrds_identity_page_inactive_account(self):
        account = self.factory.make_account(status=AccountStatus.DEACTIVATED)
        r = self.client.get("/+id/%s/+xrds" % account.openid_identifier)
        self.assertEqual(r.status_code, 404)

    def test_xrds_identity_page_active_account(self):
        account = self.factory.make_account()
        r = self.client.get("/+id/%s/+xrds" % account.openid_identifier)
        self.assert_xrds_document(r, template='person-xrds.xml')


class OpenIDAuthorizedTestCase(AuthenticatedTestCase):

    def setUp(self):
        super(OpenIDAuthorizedTestCase, self).setUp()

        self.request = DummyRequest()
        self.request.user = self.account
        # we use now() here because last_login maps to django's auth model
        # which uses localtime.
        self.request.user.last_login = datetime.datetime.now()
        self.orequest = DummyORequest()
        self.orequest.identity = (settings.SSO_ROOT_URL + '+id/' +
                                  self.account.openid_identifier)
        self.pape_mock = self._apply_patch('openid.extensions.pape.Request')
        self.pape_mock.fromOpenIDRequest.return_value = None

    def test_openid_is_authorized_not_authenticated(self):
        self.request.user = AnonymousUser()
        r = server._openid_is_authorized(self.request, self.orequest)
        self.assertFalse(r)

    def test_openid_is_authorized_id_owner(self):
        self.orequest.identity = 'http://localhost/+id/mark_oid'
        r = server._openid_is_authorized(self.request, self.orequest)
        self.assertFalse(r)

    @switches(TWOFACTOR=True)
    def test_openid_is_authorized_complex_2f_for_site(self):
        # this test covers a bug in a very specific condition
        # user is logged in, but not 2f-authenticated
        # site requires 2f and is set to auto_authorize
        OpenIDRPConfig.objects.create(
            trust_root=self.orequest.trust_root,
            require_two_factor=True,
            auto_authorize=True,
        )
        r = server._openid_is_authorized(self.request, self.orequest)
        self.assertFalse(r)

    @switches(TWOFACTOR=False)
    def test_openid_is_authorized_complex_2f_disabled(self):
        # this test covers a bug in a very specific condition
        # user is logged in, but not 2f-authenticated
        # site requires 2f and is set to auto_authorize
        OpenIDRPConfig.objects.create(
            trust_root=self.orequest.trust_root,
            require_two_factor=True,
            auto_authorize=True,
        )
        r = server._openid_is_authorized(self.request, self.orequest)
        self.assertTrue(r)

    def test_openid_is_authorized_should_reauthenticate(self):
        self.pape_mock.fromOpenIDRequest.return_value = Mock()
        self.pape_mock.fromOpenIDRequest.return_value.max_auth_age = '0'

        r = server._openid_is_authorized(self.request, self.orequest)
        self.assertFalse(r)

    def test_openid_is_authorized_rpconfig(self):
        OpenIDRPConfig.objects.create(
            trust_root=self.orequest.trust_root, auto_authorize=True)

        r = server._openid_is_authorized(self.request, self.orequest)
        self.assertTrue(r)

    def test_openid_is_authorized_other(self):
        r = server._openid_is_authorized(self.request, self.orequest)
        self.assertFalse(r)

        expires = datetime.datetime.utcnow() + datetime.timedelta(1)
        OpenIDAuthorization.objects.authorize(
            self.request.user,
            self.orequest.trust_root, expires,
            self.request.session.session_key,
        )

        r = server._openid_is_authorized(self.request, self.orequest)
        self.assertTrue(r)


class ShouldReauthenticateTestCase(SSOBaseTestCase):

    def setUp(self):
        super(ShouldReauthenticateTestCase, self).setUp()
        self.user = self.factory.make_account()
        self.orequest = DummyORequest()
        self.orequest.identity = (settings.SSO_ROOT_URL + '+id/' +
                                  self.user.openid_identifier)

        self.pape_mock = self._apply_patch('openid.extensions.pape.Request')

    def test_should_reauthenticate_no_pape(self):
        r = server._should_reauthenticate(self.orequest, self.user)
        self.assertFalse(r)

    def test_should_reauthenticate_no_pape_max_auth_age(self):
        # pape_request.max_auth_age is None
        self.pape_mock.fromOpenIDRequest.return_value.max_auth_age = None

        r = server._should_reauthenticate(self.orequest, self.user)
        self.assertFalse(r)

    def test_should_reauthenticate_invalid_max_auth_age(self):
        # max_auth_age raise ValueError
        self.pape_mock.fromOpenIDRequest.return_value.max_auth_age = 'bad-val'

        r = server._should_reauthenticate(self.orequest, self.user)
        self.assertFalse(r)

    def test_should_reauthenticate_true(self):
        # last_login <= cutoff
        self.pape_mock.fromOpenIDRequest.return_value.max_auth_age = '0'
        # we use now() here because last_login maps to django's auth model
        # which uses localtime.
        self.user.last_login = datetime.datetime.now()

        r = server._should_reauthenticate(self.orequest, self.user)
        self.assertTrue(r)

    def test_should_reauthenticate_false(self):
        # last_login > cutoff
        self.pape_mock.fromOpenIDRequest.return_value.max_auth_age = '100'
        # we use now() here because last_login maps to django's auth model
        # which uses localtime.
        self.user.last_login = datetime.datetime.now()

        r = server._should_reauthenticate(self.orequest, self.user)
        self.assertFalse(r)


class UntrustedRPTestCase(SSOBaseTestCase):

    email = 'mark@example.com'

    def setUp(self):
        super(UntrustedRPTestCase, self).setUp()
        self.factory.make_account(email=self.email,
                                  password=DEFAULT_USER_PASSWORD)
        # Ensure that we're restricting RPs for these tests
        p = patch_settings(SSO_RESTRICT_RP=True)
        p.start()
        self.addCleanup(p.stop)

    def test_process_unknown_rp(self):
        orequest = DummyORequest()
        request = DummyRequest()
        response = server._process_openid_request(request, orequest, None)
        self.assertEqual(302, response.status_code)
        self.assert_(response['Location'].endswith('+untrusted'))

    def test_untrusted(self):
        request = {'openid.mode': 'checkid_setup',
                   'openid.trust_root': 'http://localhost/',
                   'openid.return_to': 'http://localhost/',
                   'openid.identity': IDENTIFIER_SELECT}
        openid_server = server._get_openid_server()
        orequest = openid_server.decodeRequest(request)
        token = create_token(16)

        # call up a session-modifying view to get a real session object
        r = self.client.login(username=self.email,
                              password=DEFAULT_USER_PASSWORD)
        self.assertTrue(r)

        session = self.client.session
        session[token] = signed.dumps(orequest,
                                      settings.SECRET_KEY)
        session.save()

        r = self.client.get("/%s/+untrusted" % token)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'server/untrusted.html')


class TestSregFields(SSOBaseTestCase):

    def setUp(self):
        super(TestSregFields, self).setUp()

        self.account = Account.objects.create(
            creation_rationale=AccountCreationRationale.USER_CREATED,
            status=AccountStatus.ACTIVE,
            displayname='User')

        lp_account = randint(1, 9999)
        LPOpenIdIdentifier.objects.create(
            identifier=self.account.openid_identifier,
            lp_account=lp_account)
        person = Person.objects.create(lp_account=lp_account)
        now = datetime.datetime.utcnow()
        PersonLocation.objects.create(
            date_created=now, person=person, time_zone='UTC',
            last_modified_by=person, date_last_modified=now)
        self.sreg_request = SRegRequest()
        self.rpconfig = OpenIDRPConfig()
        self.request = DummyRequest()
        self.request.user = self.account


class MarkupTestCase(AuthenticatedTestCase):

    def test_untrusted_rp_properly_shows_markup(self):
        self.rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://localhost/',
            displayname="MYSITE"
        )

        params = {
            'openid.trust_root': 'http://localhost/',
            'openid.return_to': 'http://localhost/',
            'openid.identity': IDENTIFIER_SELECT,
            'openid.claimed_id': 'http://localhost/~userid',
            'openid.ns': OPENID2_NS,
            'openid.mode': 'checkid_setup'
        }

        response = self.client.get(
            reverse('server-openid'), params, follow=True)
        self.assertContains(response, 'MYSITE')


class ApprovedDataTestCase(SSOBaseTestCase):

    def _get_openid_request(
            self, with_sreg=True, with_ax=True, with_teams=True):
        request = {
            'openid.mode': 'checkid_setup',
            'openid.trust_root': 'http://localhost/',
            'openid.return_to': 'http://localhost/',
            'openid.identity': IDENTIFIER_SELECT}
        if with_sreg:
            request['openid.sreg.required'] = 'email,fullname'
        if with_ax:
            request['openid.ns.ax'] = AXMessage.ns_uri
            request['openid.ax.mode'] = FetchRequest.mode
            request['openid.ax.type.fullname'] = AX_URI_FULL_NAME
            request['openid.ax.type.email'] = AX_URI_EMAIL
            request['openid.ax.required'] = 'email,fullname'
        if with_teams:
            request['openid.lp.query_membership'] = 'ubuntu-team'
        openid_server = server._get_openid_server()
        return openid_server.decodeRequest(request)

    def _get_request_with_post_args(self, args={}):
        request = HttpRequest()
        request.user = self.account
        request.POST = args
        request.META = {'REQUEST_METHOD': 'POST'}
        return request

    def setUp(self):
        super(ApprovedDataTestCase, self).setUp()

        # Ensure that we're restricting RPs for these tests
        p = patch_settings(SSO_RESTRICT_RP=False)
        p.start()
        self.addCleanup(p.stop)

        self.account = self.factory.make_account(teams=['ubuntu-team'])

    def test_approved_data_returns_none_for_no_request(self):
        result = server._get_approved_data(HttpRequest(), None)
        self.assertEqual(result, None)

    def test_approved_data_for_sreg_only(self):
        post_args = {'email': 'email', 'ubuntu-team': 'ubuntu-team'}
        result = server._get_approved_data(
            self._get_request_with_post_args(post_args),
            self._get_openid_request(with_sreg=True, with_ax=False,
                                     with_teams=False))
        self.assertEqual(sorted(result['user_attribs']['requested']),
                         ['email', 'fullname'])
        self.assertEqual(result['user_attribs']['approved'], ['email'])
        self.assertNotIn('teams', result)

    def test_approved_data_for_ax_only(self):
        post_args = {'email': 'email', 'ubuntu-team': 'ubuntu-team'}
        result = server._get_approved_data(
            self._get_request_with_post_args(post_args),
            self._get_openid_request(with_sreg=False, with_ax=True,
                                     with_teams=False))
        self.assertEqual(sorted(result['user_attribs']['requested']),
                         ['email', 'fullname'])
        self.assertEqual(result['user_attribs']['approved'], ['email'])
        self.assertNotIn('teams', result)

    def test_approved_data_for_teams_only(self):
        post_args = {'ubuntu-team': 'ubuntu-team'}
        result = server._get_approved_data(
            self._get_request_with_post_args(post_args),
            self._get_openid_request(with_sreg=False, with_ax=False,
                                     with_teams=True))
        self.assertEqual(result['teams']['requested'], ['ubuntu-team'])
        self.assertEqual(result['teams']['approved'], ['ubuntu-team'])
        self.assertNotIn('user_attribs', result)

    def test_approved_data_for_sreg_and_teams(self):
        post_args = {'email': 'email', 'ubuntu-team': 'ubuntu-team'}
        result = server._get_approved_data(
            self._get_request_with_post_args(post_args),
            self._get_openid_request(with_sreg=True, with_ax=False,
                                     with_teams=True))
        self.assertEqual(sorted(result['user_attribs']['requested']),
                         ['email', 'fullname'])
        self.assertEqual(result['user_attribs']['approved'], ['email'])
        self.assertEqual(result['teams']['requested'], ['ubuntu-team'])
        self.assertEqual(result['teams']['approved'], ['ubuntu-team'])

    def test_approved_data_for_ax_and_teams(self):
        post_args = {'email': 'email', 'ubuntu-team': 'ubuntu-team'}
        result = server._get_approved_data(
            self._get_request_with_post_args(post_args),
            self._get_openid_request(with_sreg=False, with_ax=True,
                                     with_teams=True))
        self.assertEqual(sorted(result['user_attribs']['requested']),
                         ['email', 'fullname'])
        self.assertEqual(result['user_attribs']['approved'], ['email'])
        self.assertEqual(result['teams']['requested'], ['ubuntu-team'])
        self.assertEqual(result['teams']['approved'], ['ubuntu-team'])


class TokenLoginTestCase(SSOBaseTestCase):
    url = reverse('login_by_token')

    @switches(LOGIN_BY_TOKEN=True)
    def test_session_is_created_via_token(self):
        token = self.factory.make_oauth_token()
        header = authorization_header_from_token(self.url, token)

        response = self.client.get(self.url, **header)
        self.assertEqual(response.status_code, 302)
        self.assertEqual('http://testserver/', response['location'])
        # session *should* contain a user id
        session = response.client.session
        self.assertIn('_auth_user_id', session)

    @switches(LOGIN_BY_TOKEN=True)
    def test_can_make_authenticated_calls(self):
        token = self.factory.make_oauth_token()
        # try to make an authenticated call without logging in by token
        url = '/+emails'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response['location'].endswith('/+login?next=/%2Bemails'))
        expected = '<h1 class="main">Your email addresses</h1>'
        self.assertNotIn(expected, response.content)

        # make the call to login_by_token
        header = authorization_header_from_token(self.url, token)
        response = self.client.get(self.url, **header)

        # again, try to make an authenticated call
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(expected, response.content)

    @switches(LOGIN_BY_TOKEN=True)
    def test_works_when_already_logged_in(self):
        token = self.factory.make_oauth_token()
        self.client.login(username=token.consumer.user.username,
                          password='test')
        url = self.url + '?next=/%2Bemails'
        header = authorization_header_from_token(url, token)

        response = self.client.get(url, **header)

        self.assertEqual(302, response.status_code)
        self.assertTrue(response['location'].endswith('/+emails'))

    @switches(LOGIN_BY_TOKEN=True)
    def test_bogus_token_does_not_login(self):
        token = self.factory.make_oauth_token()
        # make sure we have a bad token
        old_token = token.token
        token.token = 'bogus'
        header = authorization_header_from_token(self.url, token)
        response = self.client.get(self.url, **header)
        self.assertEqual(response.status_code, 403)

        # restore the token and try again
        token.token = old_token
        header = authorization_header_from_token(self.url, token)
        response = self.client.get(self.url, **header)
        self.assertEqual(response.status_code, 302)
        self.assertEqual('http://testserver/', response['location'])

    def test_settings_change_response(self):
        with switches(LOGIN_BY_TOKEN=True):
            token = self.factory.make_oauth_token()
            header = authorization_header_from_token(self.url, token)
            response = self.client.get(self.url, **header)
            self.assertEqual(response.status_code, 302)
            self.assertEqual('http://testserver/', response['location'])
        # Now do the same thing with the setting set to False
        with switches(LOGIN_BY_TOKEN=False):
            token = self.factory.make_oauth_token()
            header = authorization_header_from_token(self.url, token)
            response = self.client.get(self.url, **header)
            self.assertEqual(404, response.status_code)

    @switches(LOGIN_BY_TOKEN=True)
    def test_next_step_to_internal_url(self):
        token = self.factory.make_oauth_token()
        url = self.url + '?next=/%2Bemails'
        header = authorization_header_from_token(url, token)

        response = self.client.get(url, **header)
        self.assertEqual(302, response.status_code)
        self.assertTrue(response['location'].endswith('/+emails'))

    @switches(LOGIN_BY_TOKEN=True)
    def test_next_step_to_known_openidrp(self):
        """Check that redirecting to a trusted RP works"""
        OpenIDRPConfig.objects.create(trust_root='http://foo.com/')
        token = self.factory.make_oauth_token()
        next_step = 'http://foo.com/bar/bla'
        url = self.url + '?next=' + next_step
        header = authorization_header_from_token(url, token)

        response = self.client.get(url, **header)
        self.assertEqual(302, response.status_code)
        self.assertEqual(next_step, response['location'])

    @switches(LOGIN_BY_TOKEN=True)
    def test_invalid_next_steps(self):
        """Invalid next steps are redirected to '/' with a message."""
        for next_step in ['http://foo.com/bar/bla', '/invalid/url']:
            token = self.factory.make_oauth_token()
            url = self.url + '?next=' + next_step
            header = authorization_header_from_token(url, token)

            response = self.client.get(url, **header)
            self.assertEqual(302, response.status_code)
            self.assertEqual('http://testserver/', response['location'])
            response = self.client.get('/')
            self.assertContains(
                response, "Unknown redirect URL &#39;%s&#39;" % next_step)
