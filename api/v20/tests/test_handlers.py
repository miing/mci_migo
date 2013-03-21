from django.utils import simplejson as json

from django.core import mail
from django.core.urlresolvers import NoReverseMatch, reverse
from mock import ANY, patch

from identityprovider.models import (
    Account,
    AuthToken,
    EmailAddress,
)
from identityprovider.models.const import (
    AccountStatus,
    EmailStatus,
    TokenType,
)
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import (
    SSOBaseTestCase,
    authorization_header_from_token,
    patch_settings,
)

from api.v20 import handlers


class POSTOnlyResourceMixin(object):
    def do_post(self, data=None):
        if data is None:
            data = getattr(self, 'data', {})
        json_data = json.dumps(data)
        return self.client.post(self.url, data=json_data,
                                content_type='application/json')

    def test_get_not_allowed(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.get('Allow', ''), 'POST')

    def test_requires_post_data_json_encoded(self):
        response = self.client.post(self.url, data={'foo': ['bar', 'baz']})
        self.assertContains(response, 'Bad Request', status_code=400)


class AccountsHandlerTestCase(SSOBaseTestCase):
    fixtures = ["test"]
    url_name = 'api-account'

    def setUp(self):
        super(AccountsHandlerTestCase, self).setUp()
        self.account = Account.objects.get_by_email('test@canonical.com')
        self.url = reverse(self.url_name,
                           args=(self.account.openid_identifier,))

    def test_openid_empty(self):
        self.assertRaises(NoReverseMatch, reverse, self.url_name, args=('',))

    def test_unauthenticated_gives_minimal(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content),
                         handlers.get_minimal_account_data(self.account))

    def test_authenticated_with_django_gives_minimal(self):
        assert self.client.login(username='test@canonical.com',
                                 password=DEFAULT_USER_PASSWORD)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content),
                         handlers.get_minimal_account_data(self.account))

    def test_authenticated_with_oauth(self):
        token = self.account.create_oauth_token('token-name')
        header = authorization_header_from_token(self.url, token)
        response = self.client.get(self.url, **header)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content),
                         handlers.get_account_data(self.account))

    def test_authenticated_openid_no_match(self):
        token = self.account.create_oauth_token('token-name')
        assert self.account.openid_identifier != 'foo'
        url = reverse(self.url_name, args=('foo',))
        header = authorization_header_from_token(url, token)
        response = self.client.get(url, **header)

        self.assertEqual(response.status_code, 404)

    def test_get_account_data_no_preferred_email(self):
        account = self.account
        account.emailaddress_set.all().delete()

        assert account.preferredemail is None
        result = handlers.get_account_data(account)

        self.assertIsNone(result['email'])

    def test_get_account_data_verified(self):
        account = self.account
        assert account.emailaddress_set.verified().count() > 0

        result = handlers.get_account_data(account)
        self.assertTrue(result['verified'])

    def test_get_account_data_no_verified(self):
        account = self.account
        account.emailaddress_set.verified().delete()

        result = handlers.get_account_data(account)
        self.assertFalse(result['verified'])


class RequestsTestCase(SSOBaseTestCase, POSTOnlyResourceMixin):
    url_name = 'api-requests'
    default_http_method = 'GET'

    def setUp(self):
        super(RequestsTestCase, self).setUp()
        self.account = self.factory.make_account()
        self.url = reverse(self.url_name)

        self.external_url = 'http://example.com/foo/bar?some=1&nothing=foo'
        token = self.account.create_oauth_token('token-name')
        header = authorization_header_from_token(
            self.external_url, token, http_method=self.default_http_method)
        self.data = dict(
            http_url=self.external_url,
            http_method=self.default_http_method,
            authorization=header['HTTP_AUTHORIZATION'],
        )

        self.mock_logger = self._apply_patch('api.v20.handlers.logging')

    def assert_request_response(self, response, expected):
        self.assertEqual(response.status_code, 200)
        try:
            response = json.loads(response.content)
        except:
            self.fail('Could not JSON-decode response, content is %r.' %
                      response.content)
        else:
            self.assertEqual(response, {'is_valid': expected})

    def test_invalid_if_not_method_given(self):
        self.data.pop('http_method')
        response = self.do_post()
        self.assert_request_response(response, False)

    def test_invalid_if_method_none(self):
        self.data['http_method'] = None
        response = self.do_post()
        self.assert_request_response(response, False)
        self.mock_logger.exception.assert_called_once_with(
            'RequestsHandler.create: could not verify request:')

    def test_invalid_if_not_url_given(self):
        self.data.pop('http_url')
        response = self.do_post()
        self.assert_request_response(response, False)

    def test_invalid_if_url_none(self):
        self.data['http_url'] = None
        response = self.do_post()
        self.assert_request_response(response, False)
        self.mock_logger.exception.assert_called_once_with(
            'RequestsHandler.create: could not build OAuthRequest with the '
            'given parameters %r:', self.data)

    def test_invalid_if_not_header_given(self):
        self.data.pop('authorization')
        response = self.do_post()
        self.assert_request_response(response, False)

    def test_invalid_if_header_none(self):
        self.data['authorization'] = None
        response = self.do_post()
        self.assert_request_response(response, False)
        self.mock_logger.exception.assert_called_once_with(
            'RequestsHandler.create: could not build OAuthRequest with the '
            'given parameters %r:', self.data)

    def test_url_mismatch(self):
        new_url = self.external_url[:-1]
        assert new_url != self.external_url
        self.data['http_url'] = new_url
        response = self.do_post()

        self.assert_request_response(response, False)

    def test_method_mismatch(self):
        self.data['http_method'] = self.default_http_method * 2
        response = self.do_post()

        self.assert_request_response(response, False)

    def test_valid_request(self):
        # do a post with correct params
        response = self.do_post()

        self.assertEqual(response.status_code, 200)
        self.assert_request_response(response, True)

    def test_valid_request_for_non_existent_account(self):
        self.account.delete()
        # do a post with correct params for a non existent account
        response = self.do_post()

        self.assert_request_response(response, False)

    def test_valid_request_for_inactive_account(self):
        for status, name in AccountStatus._get_choices():
            if status == AccountStatus.ACTIVE:
                continue
            self.account.status = status
            self.account.save()
            # do a post with correct params for an inactive account
            response = self.do_post()

            self.assert_request_response(response, False)


class RequestsWithHEADTestCase(RequestsTestCase):
    default_http_method = 'HEAD'


class RequestsWithDELETETestCase(RequestsTestCase):
    default_http_method = 'DELETE'


class RequestsWithPATCHTestCase(RequestsTestCase):
    default_http_method = 'PATCH'


class RequestsWithPOSTTestCase(RequestsTestCase):
    default_http_method = 'POST'


class RequestsWithPUTTestCase(RequestsTestCase):
    default_http_method = 'PUT'


class PasswordResetTokenHandlerTestCase(SSOBaseTestCase,
                                        POSTOnlyResourceMixin):
    url_name = 'api-password-reset'

    def setUp(self):
        super(PasswordResetTokenHandlerTestCase, self).setUp()

        self.account = self.factory.make_account()
        self.email = EmailAddress.objects.get(account=self.account)
        self.token = self.factory.make_authtoken(
            token_type=TokenType.PASSWORDRECOVERY, email=self.email.email)
        self.url = reverse(self.url_name)

    def test_email_missing(self):
        response = self.do_post()
        self.assertEqual(response.status_code, 400)
        content = json.loads(response.content)
        self.assertEqual(content, {
            'message': 'Invalid request data',
            'code': 'INVALID_DATA',
            'extra': {'email': 'Field required'}})

    def test_invalid_email(self):
        response = self.do_post({'email': 'invalid@foo.com'})
        self.assertEqual(response.status_code, 400)
        content = json.loads(response.content)
        self.assertEqual(content, {
            'message': 'Invalid request data',
            'code': 'INVALID_DATA',
            'extra': {
                'email': 'No account associated with invalid@foo.com'}})

    def test_suspended_account(self):
        self.account.suspend()

        assert not self.account.can_reset_password
        response = self.do_post({'email': self.email.email})

        self.assertEqual(response.status_code, 403)
        content = json.loads(response.content)
        self.assertEqual(content, {
            'message': 'Your account has been suspended. Please contact '
                       'login support to re-enable it',
            'code': 'ACCOUNT_SUSPENDED',
            'extra': {}})

    def test_deactivated_account(self):
        self.account.status = AccountStatus.DEACTIVATED
        self.account.save()

        name = 'identityprovider.models.account.Account.can_reset_password'
        with patch(name, False):
            response = self.do_post({'email': self.email.email})

        self.assertEqual(response.status_code, 403)
        content = json.loads(response.content)
        self.assertEqual(content, {
            'message': 'Your account has been deactivated. To reactivate it, '
                       'please reset your password',
            'code': 'ACCOUNT_DEACTIVATED',
            'extra': {}})

    def test_can_not_reset_password(self):
        name = 'identityprovider.models.account.Account.can_reset_password'
        with patch(name, False):
            response = self.do_post({'email': self.email.email})

        self.assertEqual(response.status_code, 403)
        content = json.loads(response.content)
        self.assertEqual(content, {
            'message': 'Can not reset password. Please contact login support',
            'code': 'CAN_NOT_RESET_PASSWORD',
            'extra': {}})

    def test_reset_password(self):
        email = self.email.email
        response = self.do_post({'email': email})

        self.assertEqual(response.status_code, 201)
        body = json.loads(response.content)
        self.assertEqual(body['email'], email)

        tokens = AuthToken.objects.filter(
            email=self.account.preferredemail,
            token_type=TokenType.PASSWORDRECOVERY)
        token = tokens.order_by('-date_created')[0]

        self.assertEqual(len(mail.outbox), 1)
        mail_content = unicode(mail.outbox[0].message())
        self.assertIn(token.token, mail_content)
        self.assertIn(email, mail_content)

    def test_reset_password_uses_preferredemail(self):
        email = self.factory.make_email_for_account(
            self.account, status=EmailStatus.PREFERRED)
        response = self.do_post({'email': self.email.email})

        self.assertEqual(response.status_code, 201)

        tokens = AuthToken.objects.filter(
            token_type=TokenType.PASSWORDRECOVERY,
            email=self.account.preferredemail)
        self.assertEqual(tokens.count(), 1)

        self.assertEqual(len(mail.outbox), 1)
        mail_content = unicode(mail.outbox[0].message())
        self.assertIn(email.email, mail_content)
        self.assertNotIn(self.email.email, mail_content)

    def test_too_many_tokens(self):
        with patch_settings(MAX_PASSWORD_RESET_TOKENS=0):
            response = self.do_post({'email': self.email.email})

        self.assertEqual(response.status_code, 403)
        content = json.loads(response.content)
        self.assertEqual(content, {
            'message': 'Too many non-consumed tokens exist. Further token '
                       'creation is not allowed until existing tokens '
                       'are consumed.',
            'code': 'TOO_MANY_TOKENS',
            'extra': {}})

    def test_too_many_active_tokens(self):
        self.token.consume()
        tokens = AuthToken.objects.filter(
            token_type=TokenType.PASSWORDRECOVERY, email=self.email)
        assert tokens.count() == 1
        assert tokens.filter(date_consumed=None).count() == 0

        with patch_settings(MAX_PASSWORD_RESET_TOKENS=1):
            response = self.do_post({'email': self.email.email})
            self.assertEqual(response.status_code, 201)

            response = self.do_post({'email': self.email.email})
            self.assertEqual(response.status_code, 403)
            content = json.loads(response.content)
            self.assertEqual(content, {
                'message': 'Too many non-consumed tokens exist. Further '
                           'token creation is not allowed until existing '
                           'tokens are consumed.',
                'code': 'TOO_MANY_TOKENS',
                'extra': {}})

    def test_invalidated_email(self):
        invalidated_email = self.email.invalidate()

        response = self.do_post({'email': invalidated_email.email})

        self.assertEqual(response.status_code, 403)
        content = json.loads(response.content)
        self.assertEqual(content, {
            'message': ANY,
            'code': 'EMAIL_INVALIDATED',
            'extra': {}})
