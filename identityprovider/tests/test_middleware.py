# Copyright 2011 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import re
import sys
from time import sleep

from django.conf import settings
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.test import TestCase
from django.contrib.auth.models import User, AnonymousUser

from mock import patch
from openid.message import IDENTIFIER_SELECT, OPENID1_URL_LIMIT, OPENID2_NS
from u1testutils.django import patch_settings

from identityprovider.middleware import exception, util as middleware_util
from identityprovider.middleware.useraccount import (
    UserAccountConversionMiddleware)
from identityprovider.models import Account, EmailAddress, OpenIDRPConfig
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import MockRequest, SSOBaseTestCase
from identityprovider.views import testing as test_views


def _extract_csrf_token(response):
    csrf_field = re.search('<input [^>]*name=[\'"]csrfmiddlewaretoken[\'"]'
                           '[^>]*/>', response.content)
    return csrf_field and re.search(' value=[\'"]([^\'"]+)[\'"]',
                                    csrf_field.group()).group(1)


class UserAccountConversionMiddlewareTestCase(SSOBaseTestCase):

    fixtures = ['test']

    def setUp(self):
        super(UserAccountConversionMiddlewareTestCase, self).setUp()

        email = EmailAddress.objects.get(email__iexact='test@canonical.com')
        self.account = email.account
        self.middleware = UserAccountConversionMiddleware()
        self.user, _ = User.objects.get_or_create(
            username=self.account.openid_identifier)

    def test_when_not_admin_and_user_object_in_request(self):
        request = MockRequest('/')
        request.user = self.user

        self.middleware.process_request(request)

        self.assertTrue(isinstance(request.user, Account))

    def test_when_not_admin_and_user_object_in_request_have_no_account(self):
        request = MockRequest('/')
        request.user = User(username='fail')

        self.middleware.process_request(request)

        self.assertTrue(request.user, AnonymousUser)

    def test_when_admin_and_account_object_in_request(self):
        request = MockRequest('/admin/test')
        request.user = self.account

        self.middleware.process_request(request)

        self.assertTrue(isinstance(request.user, User))

    def test_when_admin_and_account_object_in_request_have_no_user(self):
        request = MockRequest('/admin/test')
        self.account.openid_identifier = "non-existing"
        request.user = self.account

        self.middleware.process_request(request)

        self.assertTrue(isinstance(request.user, AnonymousUser))


class UtilTestCase(TestCase):

    POST_PASSWORD = 'P1!2@3#'
    POST_SECRET = 'P2@3#4$'
    POST_PRIVATE = 'P3#4$5%'
    GET_PASSWORD = 'G1!2@3#'
    GET_SECRET = 'G2@3#4$'
    GET_PRIVATE = 'G3#4$5%'
    POST_PUBLIC = 'Canonical Rocks!'
    GET_PUBLIC = 'Canonical Rocks!'
    asterisks = '********'

    def test_request_sanitization(self):
        request = MockRequest('/login')
        request.POST = {}
        request.GET = {}
        request.COOKIES = {}
        request.META = {'SERVER_NAME': 'localhost', 'SERVER_PORT': 80}
        request.POST['post_password'] = self.POST_PASSWORD
        request.POST['post_secret'] = self.POST_SECRET
        request.POST['post_private'] = self.POST_PRIVATE
        request.POST['post_public'] = self.POST_PUBLIC
        request.GET['get_password'] = self.GET_PASSWORD
        request.GET['get_secret'] = self.GET_SECRET
        request.GET['get_private'] = self.GET_PRIVATE
        request.GET['get_public'] = self.GET_PUBLIC

        req = middleware_util._sanitize_request(request)

        #  Make sure sensitive data is no longer in the request
        self.assertFalse(self.POST_PASSWORD in req.POST.values())
        self.assertFalse(self.POST_SECRET in req.POST.values())
        self.assertFalse(self.POST_PRIVATE in req.POST.values())
        self.assertFalse(self.GET_PASSWORD in req.GET.values())
        self.assertFalse(self.GET_SECRET in req.GET.values())
        self.assertFalse(self.GET_PRIVATE in req.GET.values())
        #  Make sure sensitive data is replaced by asterisks
        self.assertEqual(req.POST['post_password'], self.asterisks)
        self.assertEqual(req.POST['post_secret'], self.asterisks)
        self.assertEqual(req.POST['post_private'], self.asterisks)
        self.assertEqual(req.GET['get_password'], self.asterisks)
        self.assertEqual(req.GET['get_secret'], self.asterisks)
        self.assertEqual(req.GET['get_private'], self.asterisks)
        #  Make sure public data is unaffected
        self.assertEqual(req.POST['post_public'], self.POST_PUBLIC)
        self.assertEqual(req.GET['get_public'], self.GET_PUBLIC)


class ExceptionMiddlewareTestCase(TestCase):

    PRIVATE_SETTING = '7&8*9('
    PUBLIC_SETTING = 'Something public'
    FRAME_VAR = '*8*8*8*8'

    def setUp(self):
        super(ExceptionMiddlewareTestCase, self).setUp()
        self.request = MockRequest('/login')
        self.request.META = {'SERVER_NAME': 'localhost', 'SERVER_PORT': 80}
        self.middleware = exception.LogExceptionMiddleware()

    def _get_traceback_html(self):
        reporter = middleware_util._ExceptionReporter(
            self.request, *sys.exc_info())
        return reporter.get_traceback_html()

    def test_settings_sanitization(self):
        settings.PRIVATE_SETTING = self.PRIVATE_SETTING
        settings.PUBLIC_SETTING = self.PUBLIC_SETTING

        try:
            2 / 0
        except:
            html = self._get_traceback_html()

        self.assertFalse(self.PRIVATE_SETTING in html)
        self.assertTrue(self.PUBLIC_SETTING in html)

    def test_frames_sanitization(self):
        try:
            self.FRAME_VAR
            2 / 0
        except:
            html = self._get_traceback_html()

        self.assertFalse(self.FRAME_VAR in html)
        self.assertTrue('public_variable' in html)


class TimeMiddlewareTestCase(TestCase):

    @patch('identityprovider.middleware.time.log_request')
    @patch.object(test_views, 'dummy_hook')
    def _check(self, timeout_millis, sleep_secs, calls, hook, log):
        hook.return_value = HttpResponse('DONE')
        hook.side_effect = sleep(sleep_secs)
        path = reverse(test_views.dummy)
        with patch_settings(HANDLER_TIMEOUT_MILLIS=timeout_millis):
            self.client.get(path)
        self.assertEqual(hook.call_count, 1)
        self.assertEqual(log.call_count, calls)

    def test_under_time(self):
        self._check(5000, 0, 0)

    def test_over_time(self):
        self._check(1, 0.1, 1)


# The CSRF middleware requires a session cookie in order to activate.
# The tests perform a login in order to acquire this session cookie.
class CSRFMiddlewareTestCase(SSOBaseTestCase):

    fixtures = ['test']

    def _land(self, client=None):
        client = client or self.client
        client.handler.enforce_csrf_checks = True
        r = client.get('/')
        return r, _extract_csrf_token(r)

    def _login(self, client=None, csrf_token=None):
        client = client or self.client
        client.handler.enforce_csrf_checks = True
        form = {'email': 'mark@example.com', 'password': DEFAULT_USER_PASSWORD}
        if not csrf_token:
            # get the token from the login page
            r, csrf_token = self._land()
        form['csrfmiddlewaretoken'] = csrf_token
        r = client.post('/+login', form)
        self.assertIn(settings.SESSION_COOKIE_NAME, client.cookies)
        return r

    def _logout(self, client=None):
        client = client or self.client
        client.handler.enforce_csrf_checks = True
        return client.get('/+logout')

    def test_allow_with_token(self):
        self._login()
        r = self.client.get('/')
        csrf_token = _extract_csrf_token(r)
        self.assertTrue(csrf_token)
        data = {
            'displayname': 'Mark Shuttleworthy',
            'csrfmiddlewaretoken': csrf_token
        }
        r = self.client.post('/+edit', data)
        self.assertNotEquals(r.status_code, 403)

    def test_forbid_without_token(self):
        self._login()
        r = self.client.post('/+edit', {'displayname': 'Mark Shuttleworthy'})
        self.assertEqual(r.status_code, 403)

    def test_forbid_with_forged_token(self):
        self._login()
        r = self.client.post('/+edit', {
            'displayname': 'Mark Shuttleworthy',
            'csrfmiddlewaretoken': '0'})
        self.assertEqual(r.status_code, 403)

    def test_forbid_with_stolen_token(self):
        self._login()
        token = 'a'
        r, token = self._land()
        self.assertTrue(token)
        # Get a new session, but don't invalidate the old session
        self.client.cookies.clear()
        self._login()
        r = self.client.post('/+edit', {
            'displayname': 'Mark Shuttleworthy',
            'csrfmiddlewaretoken': token})
        self.assertEqual(r.status_code, 403)

    def test_403_error_page_displays_language_flag_correctly(self):
        self._login()
        r = self.client.post('/+edit', {'displayname': 'Mark Shuttleworthy'})
        self.assertContains(r, 'en.png', status_code=403)

    def test_ajax(self):
        self._login()
        _, token = self._land()
        headers = {'HTTP_X_CSRFTOKEN': token}
        r = self.client.post('/+edit', {'displayname': 'Mark Shuttleworthy'},
                             **headers)
        self.assertNotEquals(r.status_code, 403)

    def _login_multiple_windows(self, start_with_old_cookie,
                                logout_before_stale_login):

        # Multiple windows actually share a single browser state.
        window1 = self.client
        window2 = self.client

        if start_with_old_cookie:
            r1, csrf_token1 = self._land(window1)
            r1 = self._login(window1, csrf_token1)
            r1 = self._logout(window1)

        r1, csrf_token1 = self._land(window1)

        r2, csrf_token2 = self._land(window2)
        self._login(window2, csrf_token2)

        if logout_before_stale_login:
            self._logout(window2)

        r1 = self._login(window1, csrf_token1)
        self.assertNotEqual(r1.status_code, 403)

    def test_multiple_windows_no_cookie(self):
        self._login_multiple_windows(start_with_old_cookie=False,
                                     logout_before_stale_login=False)

    def test_multiple_windows_old_cookie(self):
        self._login_multiple_windows(start_with_old_cookie=True,
                                     logout_before_stale_login=False)

    def test_multiple_windows_no_cookie_logged_out(self):
        self._login_multiple_windows(start_with_old_cookie=False,
                                     logout_before_stale_login=True)

    def test_multiple_windows_old_cookie_logged_out(self):
        self._login_multiple_windows(start_with_old_cookie=True,
                                     logout_before_stale_login=True)

    def test_csrf_in_openid_forms(self):
        trust_root = 'http://localhost/'
        return_to = trust_root + (OPENID1_URL_LIMIT * 'a')

        # Setup the trust_root to be trusted for OpenID operations.
        self.rpconfig = OpenIDRPConfig(trust_root=trust_root)
        self.rpconfig.save()

        # 1. Establish a shared secret with the Provider.
        data = {
            'openid.mode': 'associate',
            'openid.assoc_type': 'HMAC-SHA1',
        }
        r = self.client.get('/+openid', data)
        [assoc_handle] = re.findall('assoc_handle:(.*)', r.content)

        # Reset cookies, just in case, because after this we pretend
        # to be the user.
        self.client.cookies.clear()

        # 2. RP directs user to Provider for checkid_setup and login.
        data = {
            'openid.mode': 'checkid_setup',
            'openid.realm': trust_root,
            'openid.return_to': return_to,
            'openid.ns': OPENID2_NS,
            'openid.identity': IDENTIFIER_SELECT,
            'openid.claimed_id': 'http://openid.launchpad.dev/+id/mark_oid',
            'openid.assoc_handle': assoc_handle,
        }
        r = self.client.get('/+openid', data, follow=True)
        self.assertTemplateUsed(r, 'registration/login.html')

        [oid_token] = re.findall(r'http://[^/]+/([^/]+)/\+decide',
                                 r.redirect_chain[-1][0])

        # 3. User logs in to SSO, but is allowed to decide whether to
        # continue back to RP.
        data = {
            'email': 'mark@example.com',
            'password': DEFAULT_USER_PASSWORD
        }
        r = self.client.post('/%s/+login' % oid_token, data, follow=True)
        self.assertTemplateUsed(r, 'server/decide.html')

        csrf_token = _extract_csrf_token(r)
        # We *must* have a CSRF token on the form that submits to SSO.
        self.assertNotEquals(csrf_token, None)

        # 4. User decides to continue on to RP.
        data = {
            'csrfmiddlewaretoken': csrf_token,
            'ok': 'ok'
        }
        r = self.client.post('/%s/+decide' % oid_token, data, follow=True)
        self.assertTemplateUsed(r, 'server/post-assertion.html')
        self.assertContains(r, '<form ')
        self.assertContains(r, 'method="post"')

        # We *must not* have a CSRF token on the form that submits
        # to the RP.
        self.assertEqual(_extract_csrf_token(r), None)
