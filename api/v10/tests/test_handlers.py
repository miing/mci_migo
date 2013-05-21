# encoding: utf-8
from django.utils import simplejson as json
from datetime import datetime, timedelta

from django.utils.http import urlencode
from django.core.urlresolvers import reverse

from mock import patch
from lazr.restfulclient.errors import HTTPError

from gargoyle import gargoyle

from identityprovider.tests.utils import SSOBaseTestCase
from identityprovider.models import (
    Account,
    APIUser,
    EmailAddress,
)
from identityprovider.models.const import (
    AccountStatus,
    EmailStatus,
    TokenType,
)
from identityprovider.tests import (
    DEFAULT_API_PASSWORD,
    DEFAULT_USER_PASSWORD,
)
from identityprovider.tests.utils import authorization_header_from_token
from identityprovider.validators import PASSWORD_POLICY_ERROR

from api.v10.handlers import AuthenticationHandler
from api.v10.tests.utils import (
    AnonAPITestCase,
    MockRequest,
    http_authorization_extra,
)


class RegistrationHandlerTestCase(AnonAPITestCase):

    def setUp(self):
        super(RegistrationHandlerTestCase, self).setUp()
        p = patch('identityprovider.emailutils.send_new_user_email')
        self.mock_send = p.start()
        self.addCleanup(p.stop)

    def test_authtoken_without_requester_is_handled_properly(self):
        authtoken = self.factory.make_authtoken(
            email="test@example.com", token_type=TokenType.PASSWORDRECOVERY)
        assert authtoken.requester is None

        response = self.api.registrations.set_new_password(
            email='test@example.com', token=authtoken.token,
            new_password='pass')
        self.assertEqual(response['status'], "error")

    def test_set_new_password_ok(self):
        email_address = self.factory.make_email_address()
        account = self.factory.make_account(email=email_address)
        account.create_oauth_token('some-token')
        authtoken = self.factory.make_authtoken(
            requester=account, requester_email=email_address,
            email=email_address, token_type=TokenType.PASSWORDRECOVERY)

        response = self.api.registrations.set_new_password(
            email=email_address, token=authtoken.token,
            new_password='testing-password')
        self.assertEqual(response['status'], "ok")
        self.assertEqual(account.oauth_tokens().count(), 0)

    def test_set_new_password_invalid(self):
        email_address = self.factory.make_email_address()
        account = self.factory.make_account(email=email_address)
        authtoken = self.factory.make_authtoken(
            requester=account, requester_email=email_address,
            email=email_address, token_type=TokenType.PASSWORDRECOVERY)

        response = self.api.registrations.set_new_password(
            email=email_address, token=authtoken.token, new_password='pass')
        self.assertEqual(response['status'], "error")
        self.assertEqual(response['errors'], [PASSWORD_POLICY_ERROR])

    def test_reset_token_when_email_is_invalid(self):
        try:
            self.api.registrations.request_password_reset_token(
                email='non-existing@example.com')
        except HTTPError, e:
            self.assertEqual(e.response.status, 403)
            self.assertEqual(e.response['content-type'], "text/plain")
            self.assertTrue(e.content.startswith("CanNotResetPasswordError:"))

    def test_reset_token_when_account_is_disabled(self):
        email_address = self.factory.make_email_address()
        self.factory.make_account(email=email_address,
                                  status=AccountStatus.SUSPENDED)

        try:
            self.api.registrations.request_password_reset_token(
                email=email_address)
        except HTTPError, e:
            self.assertEqual(e.response.status, 403)
            self.assertEqual(e.response['content-type'], "text/plain")
            self.assertTrue(e.content.startswith("CanNotResetPasswordError:"))

    def test_reset_password_when_not_existing_token_is_passed(self):
        email_address = self.factory.make_email_address()
        try:
            self.api.registrations.set_new_password(
                email=email_address, token='not-existing-token',
                new_password='password')
        except HTTPError, e:
            self.assertEqual(e.response.status, 403)
            self.assertEqual(e.response['content-type'], "text/plain")
            self.assertTrue(e.content.startswith(
                "CanNotSetPasswordError: Invalid token."))

    def test_register_email_error_is_in_list(self):
        self.factory.make_account(email='register@example.com',
                                  email_validated=False)

        response = self.api.registrations.register(
            email='register@example.com', password='blogdf3Daa',
            captcha_solution='solution', captcha_id='id')

        self.assertEqual(response['errors'],
                         {'email': ["Email already registered"]})
        self.assertFalse(self.mock_send.called)

    def test_register_without_displayname(self):
        email = self.factory.make_email_address()

        response = self.api.registrations.register(
            email=email, password='MySecretPassword1',
            captcha_solution='foobar', captcha_id='id')
        self.assertEqual(response['status'], 'ok')

        account = Account.objects.get_by_email(email)
        self.assertEqual(account.displayname, '')
        self.mock_send.assert_called_once_with(
            account, email, None, 'desktop')

    def test_register_with_displayname(self):
        email = self.factory.make_email_address()

        response = self.api.registrations.register(
            email=email, password='MySecretPassword1',
            captcha_solution='foobar', captcha_id='id',
            displayname='Test User')
        self.assertEqual(response['status'], 'ok')

        account = Account.objects.get_by_email(email)
        self.assertEqual(account.displayname, 'Test User')
        self.mock_send.assert_called_once_with(
            account, email, None, 'desktop')

    def test_register_with_lowered_password_requirements(self):
        email = self.factory.make_email_address()

        # password: 8 characters long (no uppercase or numbers, only lowercase)
        response = self.api.registrations.register(
            email=email, password='abcdefgh',
            captcha_solution='foobar', captcha_id='id',
            displayname='Test User')
        self.assertEqual(response['status'], 'ok')

        account = Account.objects.get_by_email(email)
        self.assertEqual(account.displayname, 'Test User')
        self.mock_send.assert_called_once_with(
            account, email, None, 'desktop')

    def test_register_without_platform(self):
        email = self.factory.make_email_address()

        response = self.api.registrations.register(
            email=email, password='MySecretPassword1',
            captcha_solution='foobar', captcha_id='id')
        self.assertEqual(response['status'], 'ok')

        account = Account.objects.get_by_email(email)
        self.mock_send.assert_called_once_with(
            account, email, None, 'desktop')

    def test_register_with_platform(self):
        email = self.factory.make_email_address()

        response = self.api.registrations.register(
            email=email, password='MySecretPassword1',
            captcha_solution='foobar', captcha_id='id',
            platform='mobile', displayname='Mobile User')
        self.assertEqual(response['status'], 'ok')

        account = Account.objects.get_by_email(email)
        self.mock_send.assert_called_once_with(
            None, email, None, 'mobile', password=account.encrypted_password,
            displayname='Mobile User')

    def test_register_with_invalid_platform(self):
        email = self.factory.make_email_address()

        response = self.api.registrations.register(
            email=email, password='MySecretPassword1',
            captcha_solution='foobar', captcha_id='id',
            platform='foo')

        self.assertEqual(response['status'], 'error')
        self.assertTrue('platform' in response['errors'])
        self.assertFalse(self.mock_send.called)

    def test_register_without_redirection_url(self):
        email_address = self.factory.make_email_address()

        response = self.api.registrations.register(
            email=email_address, password='MySecretPassword1',
            captcha_solution='foobar', captcha_id='id',
            platform='desktop')

        self.assertEqual(response['status'], 'ok')
        email = EmailAddress.objects.get(email=email_address)
        self.mock_send.assert_called_once_with(
            email.account, email_address, None, 'desktop')

    def test_register_from_desktop_with_redirection_url(self):
        email_address = self.factory.make_email_address()

        response = self.api.registrations.register(
            email=email_address, password='MySecretPassword1',
            captcha_solution='foobar', captcha_id='id',
            platform='desktop', validate_redirect_to='http://foo')

        self.assertEqual(response['status'], 'ok')
        email = EmailAddress.objects.get(email=email_address)
        self.mock_send.assert_called_once_with(
            email.account, email_address, 'http://foo', 'desktop')

    def test_register_from_mobile_with_redirection_url(self):
        email_address = self.factory.make_email_address()

        response = self.api.registrations.register(
            email=email_address, password='MySecretPassword1',
            captcha_solution='foobar', captcha_id='id',
            platform='mobile', validate_redirect_to='http://foo')

        self.assertEqual(response['status'], 'ok')
        account = Account.objects.get_by_email(email_address)
        if not gargoyle.is_active('ALLOW_UNVERIFIED'):
            self.assertEqual(None, account.preferredemail)
        unverified = account.unverified_emails()
        self.assertEqual([email_address],
                         [emailaddress.email for emailaddress in unverified])

    def test_register_from_mobile_without_redirection_url(self):
        email_address = self.factory.make_email_address()

        response = self.api.registrations.register(
            email=email_address, password='MySecretPassword1',
            captcha_solution='foobar', captcha_id='id',
            platform='mobile')

        self.assertEqual(response['status'], 'ok')
        account = Account.objects.get_by_email(email_address)
        if not gargoyle.is_active('ALLOW_UNVERIFIED'):
            self.assertEqual(None, account.preferredemail)

        unverified = account.unverified_emails()
        self.assertEqual([email_address],
                         [emailaddress.email for emailaddress in unverified])


class AuthenticationTestCase(SSOBaseTestCase):

    def setUp(self):
        super(AuthenticationTestCase, self).setUp()
        self.authentication = AuthenticationHandler()
        self.email_address = self.factory.make_email_address()
        self.account = self.factory.make_account(email=self.email_address)
        self.apiuser = self.factory.make_apiuser()

    def put(self, url, data, **extra):
        return self.client.put(
            url,
            urlencode(data),
            content_type='application/x-www-form-urlencoded',
            **extra
        )

    def authenticate(self, token_name='', token=None, method='GET',
                     api_version='1.0'):
        data = {
            'ws.op': 'authenticate',
            'token_name': token_name,
        }
        if token is not None:
            data['token'] = token

        extra = http_authorization_extra(self.email_address,
                                         password=DEFAULT_USER_PASSWORD)
        if method == 'PUT':
            data = urlencode(data)
            extra['content_type'] = 'application/x-www-form-urlencoded'
        dispatcher = getattr(self.client, method.lower())
        response = dispatcher("/api/%s/authentications" % api_version, data,
                              **extra)
        content = json.loads(response.content)
        return content

    def validate_token(self, token, openid, max_age=None):
        data = {
            'ws.op': 'validate_token',
            'token': token,
            'consumer_key': openid,
        }
        if max_age is not None:
            data['max_age'] = max_age
        extra = http_authorization_extra(self.apiuser.username,
                                         password=DEFAULT_API_PASSWORD)
        response = self.client.get('/api/1.0/authentications', data, **extra)
        content = json.loads(response.content)
        return content

    def test_account_by_openid_with_valid_openid(self):
        account = self.factory.make_account()
        openid = account.openid_identifier

        request = MockRequest(user=APIUser(), data={'openid': openid})

        account = self.authentication.account_by_openid(request)

        self.assertEqual(account['openid_identifier'], openid)

    def test_account_by_openid_with_invalid_openid(self):
        request = MockRequest(user=APIUser(), data={'openid': "bad-openid"})

        account = self.authentication.account_by_openid(request)

        self.assertTrue(account is None)

    def test_authenticate_unquoted_token(self):
        expected_keys = ['consumer_key', 'consumer_secret', 'name', 'token',
                         'token_secret', 'created', 'updated']

        content = self.authenticate(token_name='some-token')
        self.assertEqual(set(content.keys()), set(expected_keys))
        self.assertEqual(content['name'], 'some-token')

    def test_authenticate_quoted_token(self):
        expected_keys = ['consumer_key', 'consumer_secret', 'name', 'token',
                         'token_secret', 'created', 'updated']

        content = self.authenticate(token_name='"some-token"')
        self.assertEqual(set(content.keys()), set(expected_keys))
        self.assertEqual(content['name'], 'some-token')

    def test_team_memberships_public_teams(self):
        team = self.factory.make_team()
        otherteam = self.factory.make_team()
        self.factory.make_apiuser(username='foobar')
        account = self.factory.make_account()
        self.factory.add_account_to_team(account, team)

        # Request membership via API
        extra = http_authorization_extra('foobar',
                                         password=DEFAULT_API_PASSWORD)
        data = {
            'ws.op': 'team_memberships',
            'team_names': '["%s", "%s"]' % (team.name, otherteam.name),
            'openid_identifier': account.openid_identifier,
        }
        response = self.client.get('/api/1.0/authentications', data, **extra)
        self.assertContains(response, team.name)
        self.assertNotContains(response, otherteam.name)

    def test_team_membership_private_teams(self):
        team = self.factory.make_team(private=True)
        self.factory.make_apiuser(username='foobar')
        account = self.factory.make_account()
        self.factory.add_account_to_team(account, team)

        # Request membership via API
        extra = http_authorization_extra('foobar',
                                         password=DEFAULT_API_PASSWORD)
        data = {
            'ws.op': 'team_memberships',
            'team_names': '["%s"]' % team.name,
            'openid_identifier': account.openid_identifier,
        }
        response = self.client.get('/api/1.0/authentications', data, **extra)
        self.assertContains(response, team.name)

    def test_team_membership_basic_auth_protected(self):
        data = {
            'ws.op': 'team_memberships',
            'team_names': '["something"]',
            'openid_identifier': 'test',
        }
        response = self.client.get('/api/1.0/authentications', data)
        self.assertEqual(401, response.status_code)

    def test_team_membership_fails_for_regular_user(self):
        email_address = self.factory.make_email_address()
        self.factory.make_account(email=email_address)
        extra = http_authorization_extra(email_address,
                                         password=DEFAULT_USER_PASSWORD)
        data = {
            'ws.op': 'team_memberships',
            'team_names': '["something"]',
            'openid_identifier': 'test',
        }
        response = self.client.get('/api/1.0/authentications', data, **extra)
        self.assertEqual(403, response.status_code)

    def test_validate_unknown_token(self):
        openid = self.account.openid_identifier

        response = self.validate_token('foo', openid)
        self.assertFalse(response)

    def test_validate_token(self):
        openid = self.account.openid_identifier
        token = self.authenticate(token_name='foo')

        response = self.validate_token(token['token'], openid)
        self.assertEqual(response, token)

    def test_validate_fresh_token(self):
        openid = self.account.openid_identifier
        token = self.authenticate(token_name='foo')

        response = self.validate_token(token['token'], openid, max_age=900)
        self.assertEqual(response, token)

    def test_validate_stale_token(self):
        openid = self.account.openid_identifier
        token = self.authenticate(token_name='foo')

        updated = datetime.strptime(token['updated'], '%Y-%m-%d %H:%M:%S.%f')
        # 5 seconds have passed since we created the token
        time_at_call = updated + timedelta(seconds=5)

        class FakeDatetime(datetime):
            @staticmethod
            def utcnow():
                return time_at_call

        with patch('api.v10.handlers.datetime', FakeDatetime):
            response = self.validate_token(token['token'], openid, max_age=4)
        self.assertFalse(response)


class AccountsTestCase(SSOBaseTestCase):

    url = reverse('api-10-accounts')

    def auth_header(self, token, url=None, parameters=None):
        if url is None:
            url = self.url
        return authorization_header_from_token(url, token, http_method='GET',
                                               parameters=parameters)

    def test_me_is_oauth_protected(self):
        email_address = self.factory.make_email_address()
        extra = http_authorization_extra(email_address,
                                         password=DEFAULT_USER_PASSWORD)
        data = {'ws.op': 'me'}
        response = self.client.get(self.url, data, **extra)
        self.assertEqual(401, response.status_code)

    def test_me_success(self):
        name = u'Ñânḑù'
        account = self.factory.make_account(displayname=name)
        token = account.create_oauth_token('token-name')

        data = {'ws.op': 'me'}
        response = self.client.get(
            self.url, data, **self.auth_header(token, parameters=data))

        data = json.loads(unicode(response.content))
        expected = ['username', 'preferred_email', 'displayname',
                    'unverified_emails', 'verified_emails',
                    'openid_identifier']
        self.assertEqual(set(expected), set(data.keys()))
        self.assertEqual(data['displayname'], name)

    def test_team_membership_public_teams(self):
        account = self.factory.make_account()
        team = self.factory.make_team()
        otherteam = self.factory.make_team()
        self.factory.add_account_to_team(account, team)
        token = account.create_oauth_token('token-name')

        data = {'ws.op': 'team_memberships',
                'team_names': '["%s", "%s"]' % (team.name, otherteam.name)}
        response = self.client.get(
            self.url, data, **self.auth_header(token, parameters=data))

        self.assertContains(response, team.name)
        self.assertNotContains(response, otherteam.name)

    def test_team_membership_private_teams(self):
        account = self.factory.make_account()
        team = self.factory.make_team(private=True)
        self.factory.add_account_to_team(account, team)
        token = account.create_oauth_token('token-name')

        data = {'ws.op': 'team_memberships',
                'team_names': '["%s"]' % team.name}
        response = self.client.get(
            self.url, data, **self.auth_header(token, parameters=data))

        self.assertContains(response, team.name)

    def test_validate_email_bad_token(self):
        account = self.factory.make_account()
        token = account.create_oauth_token('token-name')

        data = {'ws.op': 'validate_email', 'email_token': 'ABCD'}
        response = self.client.get(
            self.url, data, **self.auth_header(token, parameters=data))

        self.assertContains(response, 'Bad email token!')

    def test_validate_email_success(self):
        account = self.factory.make_account()
        email = self.factory.make_email_for_account(
            account, status=EmailStatus.NEW)
        authtoken = self.factory.make_authtoken(
            requester=account, email=email.email,
            token_type=TokenType.VALIDATEEMAIL)

        token = account.create_oauth_token('token-name')

        data = {'ws.op': 'validate_email', 'email_token': authtoken.token}
        response = self.client.get(
            self.url, data, **self.auth_header(token, parameters=data))

        self.assertContains(response, email.email)
        updatedemail = EmailAddress.objects.get(email=email.email)
        self.assertEqual(EmailStatus.VALIDATED, updatedemail.status)
