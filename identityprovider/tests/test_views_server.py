# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

import datetime
import urlparse

from random import randint

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.core.urlresolvers import reverse
from django.http import HttpRequest
from django.test import TestCase
from gargoyle.testutils import switches
from mock import Mock, patch
from openid.extensions.sreg import SRegRequest
from openid.message import (
    IDENTIFIER_SELECT,
    OPENID1_URL_LIMIT,
    OPENID2_NS,
    Message,
)
from openid.yadis.constants import YADIS_HEADER_NAME
from urllib import quote, quote_plus

import identityprovider.signed as signed
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
        r = self.client.get('/+openid', params)
        query = self.get_query(r)
        error_msg = 'No+mode+value+in+message+'
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'error')
        self.assertTrue(query['openid.error'].startswith(error_msg))

    def test_handle_openid_error_other(self):
        params = {'openid.mode': 'checkid_setup'}
        r = self.client.get('/+openid', params)
        error_mode = "mode:error"
        error_msg = "error:Missing required field 'return_to'"
        self.assertEqual(r.status_code, 200)
        self.assertIn(error_mode, r.content)
        self.assertIn(error_msg, r.content)


class ProcessOpenIDRequestTestCase(SSOBaseTestCase):

    # tests for the _process_openid_request method

    def test_process_openid_request_no_orequest(self):
        r = self.client.get('/+openid')
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'server/server_info.html')


class HandleUserResponseTestCase(SSOBaseTestCase):
    fixtures = ['test']

    def setUp(self):
        super(HandleUserResponseTestCase, self).setUp()

        # create a trusted rpconfig
        self.rpconfig = OpenIDRPConfig(trust_root='http://localhost/')
        self.rpconfig.save()

        self.params = {'openid.trust_root': 'http://localhost/',
                       'openid.return_to': 'http://localhost/',
                       'openid.identity': IDENTIFIER_SELECT,
                       'openid.claimed_id': 'http://localhost/~userid',
                       'openid.ns': OPENID2_NS,
                       'openid.mode': 'checkid_setup'}

    # tests for the _handle_user_response method

    def test_handle_user_response_checkid_immediate(self):
        self.params['openid.mode'] = 'checkid_immediate'

        r = self.client.get('/+openid', self.params)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'setup_needed')

    def test_handle_user_response_no_valid_openid(self):
        self.params.update({'openid.identity': 'bogus',
                            'openid.claimed_id': 'bogus'})
        r = self.client.get('/+openid', self.params)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'server/invalid_identifier.html')

    def test_handle_user_response_openid_is_authorized_idselect(self):
        # update rp to auto authorize
        self.rpconfig.auto_authorize = True
        self.rpconfig.save()

        account = Account.objects.get_by_email('mark@example.com')
        self.client.login(username='mark@example.com',
                          password=DEFAULT_USER_PASSWORD)
        r = self.client.get('/+openid', self.params)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'id_res')
        self.assertEqual(query['openid.identity'],
                         quote_plus(account.openid_identity_url))

    def test_handle_user_response_openid_is_authorized_other_id(self):
        self.rpconfig.auto_authorize = True
        self.rpconfig.save()

        self.params['openid.identity'] = \
            settings.SSO_ROOT_URL + '+id/mark_oid'
        self.client.login(username='mark@example.com',
                          password=DEFAULT_USER_PASSWORD)
        r = self.client.get('/+openid', self.params)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'id_res')
        self.assertEqual(query['openid.identity'],
                         quote_plus(self.params['openid.identity']))

    def test_handle_user_response_user_is_authenticated(self):
        self.params['openid.identity'] = \
            settings.SSO_ROOT_URL + '+id/other_oid'
        self.client.login(username='mark@example.com',
                          password=DEFAULT_USER_PASSWORD)
        r = self.client.get('/+openid', self.params)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'cancel')

    def test_handle_user_response_decide(self):
        r = self.client.get('/+openid', self.params)
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r['Location'].endswith('+decide'))

    def test_handle_user_response_with_referer(self):
        META = {'HTTP_REFERER': 'http://localhost/'}
        r = self.client.get('/+openid', self.params, **META)
        openid_referer = self.client.cookies.get('openid_referer')
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r['Location'].endswith('+decide'))
        self.assertEqual(openid_referer.value, META['HTTP_REFERER'])

    def get_login_after_redirect_from_consumer(self):
        self.rpconfig.logo = 'http://someserver/logo.png'
        self.rpconfig.save()
        r = self.client.get('/+openid', self.params, follow=True)
        return r

    def get_new_account_after_redirect_to_login_from_consumer(self):
        r = self.get_login_after_redirect_from_consumer()
        path_parts = r.request['PATH_INFO'].split('/')
        token = path_parts[1]
        new_account_url = '/%s/+new_account' % token
        r = self.client.get(new_account_url)
        return r

    def test_logo_for_rpconfig_on_decide_page(self):
        r = self.get_login_after_redirect_from_consumer()
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "<img src='http://someserver/logo.png'/>")

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


class MultiLangOpenIDTestCase(TestCase):

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
        response = self.client.get('/+openid')
        expected = "This is {0}, built on OpenID".format(
            settings.BRAND_DESCRIPTION)
        self.assertContains(response, expected)

    def test_german(self):
        response = self.client.get('/de/+openid')
        self.assertContains(response, self.flag_icon('de'))
        self.assertEqual('de', self.client.session['django_language'])

    def test_german_with_country_code(self):
        # This should default back to 'de'.
        response = self.client.get('/de_CH/+openid')
        self.assertContains(response, self.flag_icon('de'))
        self.assertEqual('de', self.client.session['django_language'])

    def test_unsupported_language(self):
        response = self.client.get('/sw/+openid')
        self.assertContains(response, self.flag_icon('en'))
        self.assertEqual('en', self.client.session['django_language'])

    def test_language_persists_in_session(self):
        self.client.get('/de/+openid')
        self.assertEqual('de', self.client.session['django_language'])
        # Requesting a second time will still bring back German
        # if no other setting takes precedence (like the user's preference)
        self.client.get('/+openid')
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


class DecideTestCase(AuthenticatedTestCase):

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

    def setUp(self):
        super(DecideTestCase, self).setUp(disableCSRF=True)
        self._apply_patch('webui.decorators.disable_cookie_check')
        self._prepare_openid_token()

    def test_decide_invalid(self):
        token = 'a' * 16
        r = self.client.get("/%s/+decide" % token)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, 'Invalid OpenID transaction')

    def test_decide_authenticated(self):
        r = self.client.post("/%s/+decide" % self.token, {'ok': 'ok'})
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
        r = self.client.post("/%s/+decide" % self.token, {'ok': ''})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r['Content-Type'], 'text/html')
        self.assertContains(r, '<form ')
        self.assertContains(r, return_to)

    def test_decide_auto_authorize(self):
        # make sure rpconfig is set to auto authorize
        rpconfig = OpenIDRPConfig(trust_root='http://localhost/',
                                  auto_authorize=True)
        rpconfig.save()

        r = self.client.post("/%s/+decide" % self.token)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'id_res')

    def test_decide_process(self):
        r = self.client.post("/%s/+decide" % self.token)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'server/decide.html')

    def test_decide_includes_rp_analytics(self):
        OpenIDRPConfig.objects.create(
            trust_root='http://localhost/',
            ga_snippet='[["_setAccount", "12345"]]')
        r = self.client.get("/%s/+decide" % self.token)

        self.assertContains(r, "_gaq.push(['_setAccount', '12345']);")

    def test_decide_not_authenticated(self):
        self.client.logout()

        # create a trusted rpconfig
        rpconfig = OpenIDRPConfig(trust_root='http://localhost/')
        rpconfig.save()

        # start openid request
        params = {'openid.trust_root': 'http://localhost/',
                  'openid.return_to': 'http://localhost/',
                  'openid.identity': IDENTIFIER_SELECT,
                  'openid.claimed_id': 'http://localhost/~userid',
                  'openid.ns': OPENID2_NS,
                  'openid.mode': 'checkid_setup'}
        r = self.client.get('/+openid', params)
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

        r = self.client.post("/%s/+decide" % self.token)
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'server/decide.html')

    def test_decide_team_membership_with_auto_authorize(self):
        # make sure rpconfig is set to auto authorize
        team_name = 'ubuntu-team'
        team = self.factory.make_team(name=team_name)
        self.factory.add_account_to_team(self.account, team)

        rpconfig = OpenIDRPConfig(trust_root='http://localhost/',
                                  auto_authorize=True)
        rpconfig.save()

        param_overrides = {
            'openid.lp.query_membership': team_name,
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        r = self.client.post("/%s/+decide" % self.token)
        query = self.get_query(r)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(query['openid.mode'], 'id_res')
        self.assertEqual(query['openid.lp.is_member'], team_name)

    def test_yui_js_url(self):
        r = self.client.get("/%s/+decide" % self.token)
        self.assertContains(
            r, '{0}lazr-js/yui/yui-min.js'.format(settings.STATIC_URL))

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

    def test_list_of_details_is_complete(self):
        team_name = 'ubuntu-team'
        team = self.factory.make_team(name=team_name)
        self.factory.add_account_to_team(self.account, team)

        # create a trusted rpconfig
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            allowed_sreg='fullname,email,language',
            can_query_any_team=True,
            description="Some description",
        )
        rpconfig.save()
        param_overrides = {
            'openid.sreg.required': 'nickname,email,fullname,language',
            'openid.lp.query_membership': team_name,
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        response = self.client.get('/%s/+decide' % self.token)
        self.assertContains(response, "Team membership")
        self.assertContains(response, "Full name")
        self.assertContains(response, "Email address")
        self.assertContains(response, "Preferred language")

    def test_state_of_checkboxes_and_data_formats_trusted(self):
        teams = ('ubuntu-team', 'launchpad-team', 'isd-team')
        for team_name in teams:
            team = self.factory.make_team(name=team_name)
            self.factory.add_account_to_team(self.account, team)

        # create a trusted rpconfig
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            allowed_sreg='nickname,email,language',
            can_query_any_team=True,
            description="Some description",
        )
        rpconfig.save()
        param_overrides = {
            'openid.sreg.required': 'nickname,email,fullname',
            'openid.sreg.optional': 'language',
            'openid.lp.query_membership': ','.join(teams),
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        response = self.client.get('/%s/+decide' % self.token)
        # checkbox checked and disabled for required fields and label is bold
        nickname = self.account.person.name
        username_html = ('<li><input checked="checked" name="nickname" '
                         'value="%s" class="required" disabled="disabled" '
                         'type="checkbox" id="id_nickname" /> <label '
                         'for="id_nickname">Username: %s</label></li>' %
                         (nickname, nickname))
        email_html = ('<li><input checked="checked" name="email" '
                      'value="%s" class="required" '
                      'disabled="disabled" type="checkbox" id="id_email" /> '
                      '<label for="id_email">Email address: %s</label></li>' %
                      (self.login_email, self.login_email))
        # checkbox checked and enabled for optional fields and label is plain
        language_html = ('<li><input checked="checked" type="checkbox" '
                         'name="language" value="en" id="id_language" /> '
                         '<label for="id_language">Preferred language: en'
                         '</label></li>')
        # team data is enabled and checked, the label is plain
        team_html_1 = ('<li><input checked="checked" type="checkbox" '
                       'name="ubuntu-team" value="ubuntu-team" id="id_'
                       'ubuntu-team" /> <label for="id_ubuntu-team">'
                       'ubuntu-team</label></li>')
        team_html_2 = ('<li><input checked="checked" type="checkbox" '
                       'name="isd-team" value="isd-team" id="id_isd-team" /> '
                       '<label for="id_isd-team">isd-team</label></li>')

        self.assertContains(response, username_html)
        self.assertContains(response, email_html)
        self.assertContains(response, language_html)
        self.assertContains(response, team_html_1)
        self.assertContains(response, team_html_2)

    def test_state_of_checkboxes_and_data_formats_untrusted(self):
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
            'openid.sreg.required': 'nickname,email,fullname',
            'openid.sreg.optional': 'language',
            'openid.lp.query_membership': 'ubuntu-team',
        }
        self._prepare_openid_token(param_overrides=param_overrides)
        response = self.client.get('/%s/+decide' % self.token)
        nickname = self.account.person.name
        # checkbox checked and *enabled* for required fields and label is bold
        username_html = ('<li><input checked="checked" name="nickname" '
                         'value="%s" class="required" type="checkbox" '
                         'id="id_nickname" /> <label for="id_nickname">'
                         'Username: %s</label></li>' % (nickname, nickname))
        email_html = ('<li><input checked="checked" name="email" '
                      'value="%s" class="required" type='
                      '"checkbox" id="id_email" /> <label for="id_email">'
                      'Email address: %s</label></li>' %
                      (self.login_email, self.login_email))
        # checkbox *not checked* and enabled for optional fields & plain label
        language_html = ('<li><input type="checkbox" name="language" value="'
                         'en" id="id_language" /> <label for="id_language">'
                         'Preferred language: en</label></li>')
        # team data is enabled and *not checked*, the label is plain
        team_html = ('<li><input type="checkbox" name="ubuntu-team" '
                     'value="ubuntu-team" id="id_ubuntu-team" /> '
                     '<label for="id_ubuntu-team">Team membership:</label> '
                     '<label for="id_ubuntu-team">ubuntu-team</label></li>')
        self.assertContains(response, username_html)
        self.assertContains(response, email_html)
        self.assertContains(response, language_html)
        self.assertContains(response, team_html)


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
        r = self.client.get('/+openid', data)
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
        super(PreAuthorizeTestCase, self).setUp(disableCSRF=True)
        self._apply_patch('webui.decorators.disable_cookie_check')
        p = patch_settings(OPENID_PREAUTHORIZATION_ACL=[
            ('http://localhost/', 'http://localhost/')
        ])
        p.start()
        self.addCleanup(p.stop)

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

        rpconfig = OpenIDRPConfig(trust_root='http://localhost/')
        rpconfig.save()

        extra = {'HTTP_REFERER': 'http://localhost/'}
        r = self.client.post('/+pre-authorize-rp',
                             {'trust_root': 'http://localhost/',
                              'callback': 'http://localhost/'},
                             **extra)
        self.assertEqual(r.status_code, 400)

    def test_pre_authorize_authenticated(self):
        rpconfig = OpenIDRPConfig(trust_root='http://localhost/')
        rpconfig.save()

        extra = {'HTTP_REFERER': 'http://localhost/'}
        r = self.client.post('/+pre-authorize-rp',
                             {'trust_root': 'http://localhost/',
                              'callback': 'http://localhost/'},
                             **extra)
        self.assertRedirects(r, 'http://localhost/')

    def test_pre_authorize_not_authenticated(self):
        rpconfig = OpenIDRPConfig(trust_root='http://localhost/')
        rpconfig.save()

        self.client.logout()
        extra = {'HTTP_REFERER': 'http://localhost/'}
        r = self.client.post('/+pre-authorize-rp',
                             {'trust_root': 'http://localhost/',
                              'callback': 'http://localhost/'},
                             **extra)
        next_url = '/+login?next=' + quote('/+pre-authorize-rp?')
        self.assertRedirects(r, next_url)

    def test_pre_authorize_after_login(self):
        rpconfig = OpenIDRPConfig(trust_root='http://localhost/')
        rpconfig.save()

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
        rpconfig = OpenIDRPConfig(trust_root='http://localhost/')
        rpconfig.save()

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
        super(CancelTestCase, self).setUp(disableCSRF=True)

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

        rpconfig = OpenIDRPConfig(trust_root='http://localhost')
        rpconfig.save()

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
        self.client.get('/+openid', self.params)

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
        rpconfig, _ = OpenIDRPConfig.objects.get_or_create(
            trust_root=self.orequest.trust_root)
        rpconfig.require_two_factor = True
        rpconfig.auto_authorize = True
        rpconfig.save()
        r = server._openid_is_authorized(self.request, self.orequest)
        self.assertFalse(r)

    @switches(TWOFACTOR=False)
    def test_openid_is_authorized_complex_2f_disabled(self):
        # this test covers a bug in a very specific condition
        # user is logged in, but not 2f-authenticated
        # site requires 2f and is set to auto_authorize
        rpconfig, _ = OpenIDRPConfig.objects.get_or_create(
            trust_root=self.orequest.trust_root)
        rpconfig.require_two_factor = True
        rpconfig.auto_authorize = True
        rpconfig.save()
        r = server._openid_is_authorized(self.request, self.orequest)
        self.assertTrue(r)

    def test_openid_is_authorized_should_reauthenticate(self):
        self.pape_mock.fromOpenIDRequest.return_value = Mock()
        self.pape_mock.fromOpenIDRequest.return_value.max_auth_age = '0'

        r = server._openid_is_authorized(self.request, self.orequest)
        self.assertFalse(r)

    def test_openid_is_authorized_rpconfig(self):
        rpconfig = OpenIDRPConfig(trust_root=self.orequest.trust_root)
        rpconfig.auto_authorize = True
        rpconfig.save()

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


class UntrustedRPTest(SSOBaseTestCase):
    fixtures = ['test']

    def setUp(self):
        super(UntrustedRPTest, self).setUp()

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
        r = self.client.login(username='mark@example.com',
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

    fixtures = ["test"]

    def setUp(self):
        super(TestSregFields, self).setUp()

        self.account = Account(
            creation_rationale=AccountCreationRationale.USER_CREATED,
            status=AccountStatus.ACTIVE,
            displayname='User')
        self.account.save()

        lp_account = randint(1, 9999)
        LPOpenIdIdentifier.objects.create(
            identifier=self.account.openid_identifier,
            lp_account=lp_account)
        person = Person(lp_account=lp_account)
        person.save()
        now = datetime.datetime.utcnow()
        personlocation = PersonLocation(date_created=now,
                                        person=person, time_zone='UTC',
                                        last_modified_by=person,
                                        date_last_modified=now)
        personlocation.save()
        self.sreg_request = SRegRequest()
        self.rpconfig = OpenIDRPConfig()
        self.request = DummyRequest()
        self.request.user = self.account


class MarkupTestCase(SSOBaseTestCase):

    fixtures = ["test"]

    def test_untrusted_rp_properly_shows_markup(self):
        self.client.login(username='mark@example.com',
                          password=DEFAULT_USER_PASSWORD)
        self.rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            displayname="MYSITE"
        )
        self.rpconfig.save()

        params = {
            'openid.trust_root': 'http://localhost/',
            'openid.return_to': 'http://localhost/',
            'openid.identity': IDENTIFIER_SELECT,
            'openid.claimed_id': 'http://localhost/~userid',
            'openid.ns': OPENID2_NS,
            'openid.mode': 'checkid_setup'
        }

        response = self.client.get('/+openid', params, follow=True)
        self.assertContains(response, 'MYSITE')


class ApprovedDataTest(SSOBaseTestCase):
    fixtures = ['test']

    def _get_openid_request(self, with_sreg=True, with_teams=True):
        request = {
            'openid.mode': 'checkid_setup',
            'openid.trust_root': 'http://localhost/',
            'openid.return_to': 'http://localhost/',
            'openid.identity': IDENTIFIER_SELECT}
        if with_sreg:
            request['openid.sreg.required'] = 'email,fullname'
        if with_teams:
            request['openid.lp.query_membership'] = 'ubuntu-team'
        openid_server = server._get_openid_server()
        return openid_server.decodeRequest(request)

    def _get_request_with_post_args(self, args={}):
        request = HttpRequest()
        request.user = Account.objects.get(pk=1)
        request.POST = args
        request.META = {'REQUEST_METHOD': 'POST'}
        return request

    def setUp(self):
        super(ApprovedDataTest, self).setUp()

        # Ensure that we're restricting RPs for these tests
        old_restrict = getattr(settings, 'SSO_RESTRICT_RP', True)
        settings.SSO_RESTRICT_RP = False
        self.addCleanup(setattr, settings, 'SSO_RESTRICT_RP', old_restrict)

    def test_approved_data_returns_none_for_no_request(self):
        result = server._get_approved_data(HttpRequest(), None)
        self.assertEqual(result, None)

    def test_approved_data_for_sreg_only(self):
        post_args = {'email': 'email', 'ubuntu-team': 'ubuntu-team'}
        result = server._get_approved_data(
            self._get_request_with_post_args(post_args),
            self._get_openid_request(True, False))
        self.assertEqual(sorted(result['sreg']['requested']),
                         ['email', 'fullname'])
        self.assertEqual(result['sreg']['approved'], ['email'])
        self.assertNotIn('teams', result)

    def test_approved_data_for_teams_only(self):
        post_args = {'ubuntu-team': 'ubuntu-team'}
        result = server._get_approved_data(
            self._get_request_with_post_args(post_args),
            self._get_openid_request(False, True))
        self.assertEqual(result['teams']['requested'], ['ubuntu-team'])
        self.assertEqual(result['teams']['approved'], ['ubuntu-team'])
        self.assertNotIn('sreg', result)

    def test_approved_data_for_sreg_and_teams(self):
        post_args = {'email': 'email', 'ubuntu-team': 'ubuntu-team'}
        result = server._get_approved_data(
            self._get_request_with_post_args(post_args),
            self._get_openid_request())
        self.assertEqual(sorted(result['sreg']['requested']),
                         ['email', 'fullname'])
        self.assertEqual(result['sreg']['approved'], ['email'])
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
