from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.core.urlresolvers import reverse
from django.http import Http404
from django.test import TestCase
from gargoyle.testutils import switches

from mock import ANY, Mock, patch, MagicMock

from identityprovider.models import InvalidatedEmailAddress, twofactor
from identityprovider.models.const import EmailStatus
from identityprovider.tests.utils import SSOBaseTestCase

from webui.decorators import (
    EMAIL_INVALIDATED,
    ratelimit,
    redirect_home_if_logged_in,
    require_twofactor_enabled,
    sso_login_required,
)


@sso_login_required(require_twofactor=True,
                    require_twofactor_freshness=True)
def view(request, *args, **kwargs):
    return 'SUCCESS'


class RequireTwofactorEnabledTestCase(TestCase):
    def setUp(self):
        super(RequireTwofactorEnabledTestCase, self).setUp()

        @require_twofactor_enabled
        def view(request):
            return 'SUCCESS'
        self.view = view

    def test_decorator_with_twofactor_enabled(self):
        request = Mock()
        name = 'webui.decorators.twofactor.is_twofactor_enabled'
        with patch(name) as mock_enabled:
            mock_enabled.return_value = True
            response = self.view(request)
        self.assertEqual(response, 'SUCCESS')

    def test_decorator_with_twofactor_disabled(self):
        request = Mock()
        name = 'webui.decorators.twofactor.is_twofactor_enabled'
        with patch(name) as mock_enabled:
            mock_enabled.return_value = False
            with self.assertRaises(Http404):
                self.view(request)


class RatelimitTestCase(TestCase):
    @patch('webui.decorators.datetime')
    def test_keys_to_check_use_utc(self, mock_datetime):
        mock_datetime.utcnow.return_value = datetime.utcnow()
        mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

        request = Mock()
        limiter = ratelimit()
        with patch.object(limiter, 'key_extra') as mock_key_extra:
            mock_key_extra.return_value = None
            limiter.keys_to_check(request)

        self.assertEqual(mock_datetime.utcnow.called, True)

    @patch('webui.decorators.datetime')
    def test_current_key_use_utc(self, mock_datetime):
        mock_datetime.utcnow.return_value = datetime.utcnow()
        mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

        request = Mock()
        limiter = ratelimit()
        with patch.object(limiter, 'key_extra') as mock_key_extra:
            mock_key_extra.return_value = None
            limiter.current_key(request)

        self.assertEqual(mock_datetime.utcnow.called, True)

    def test_disallowed_logging(self):
        limiter = ratelimit()
        limiter.remote_ip = lambda req: 33

        user1 = Mock(spec=['openid_identifier'])
        user2 = Mock(spec=['username'])
        request = Mock()

        user1.openid_identifier = user2.username = 'Username'
        user1.id = user2.id = 99

        with patch('webui.decorators.logging') as mock_logging:
            mock_logger = mock_logging.getLogger()
            for user in user1, user2:
                mock_logger.warn.reset_mock()
                request.user = user
                limiter.disallowed(request)
                mock_logger.warn.assert_called_once_with(
                    ANY, 'Username', 33, 99)


class SSOLoginRequiredTestCase(TestCase):

    @staticmethod
    def fake_view(request, *args, **kwargs):
        return "SUCCESS"

    def mock_request(self, authed, path='/'):
        mock_request = MagicMock()
        mock_request.method = 'GET'
        mock_request.user.is_authenticated.return_value = authed
        mock_request.POST = {}
        mock_request.META = {}
        mock_request.session = {}
        mock_request.build_absolute_uri.return_value = path
        mock_request.get_full_path.return_value = path
        return mock_request

    def test_django_login_check_still_works(self):
        view = sso_login_required(self.fake_view, login_url='/login')
        response = view(self.mock_request(False, '/target'))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/login?next=/target')

    @patch('webui.decorators.twofactor.'
           'user_requires_twofactor_auth')
    def test_allowed_2f_not_required(self, mock_user):
        mock_user.return_value = False
        view = sso_login_required(self.fake_view, login_url='/login')
        response = view(self.mock_request(True))
        self.assertEqual(response, 'SUCCESS')

    @patch('webui.decorators.twofactor.is_upgraded')
    @patch('webui.decorators.twofactor.'
           'user_requires_twofactor_auth')
    def test_allowed_when_2f_required_by_user_and_2f_authed(
            self, mock_user, mock_auth):
        mock_user.return_value = True
        mock_auth.return_value = True
        view = sso_login_required(self.fake_view, login_url='/login')
        response = view(self.mock_request(True))
        self.assertEqual(response, 'SUCCESS')

    @patch('webui.decorators.twofactor.is_upgraded')
    @patch('webui.decorators.twofactor.'
           'user_requires_twofactor_auth')
    def test_allowed_when_2f_required_by_keyword_and_2f_authed(
            self, mock_user, mock_auth):
        mock_user.return_value = False
        mock_auth.return_value = True
        deco = sso_login_required(require_twofactor=True, login_url='/login')
        view = deco(self.fake_view)
        response = view(self.mock_request(True))
        self.assertEqual(response, 'SUCCESS')

    @patch('webui.decorators.twofactor.is_upgraded')
    @patch('webui.decorators.twofactor.'
           'user_requires_twofactor_auth')
    def test_redirected_when_2f_required_by_user_and_not_2f_authed(
            self, mock_user, mock_auth):
        mock_user.return_value = True
        mock_auth.return_value = False
        view = sso_login_required(self.fake_view, login_url='/login')
        response = view(self.mock_request(True, '/target'))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/two_factor_auth?next=/target')

    @patch('webui.decorators.twofactor.is_upgraded')
    @patch('webui.decorators.twofactor.'
           'user_requires_twofactor_auth')
    def test_redirected_when_2f_required_by_keyword_and_not_2f_authed(
            self, mock_user, mock_auth):
        mock_user.return_value = False
        mock_auth.return_value = False
        deco = sso_login_required(require_twofactor=True, login_url='/login')
        view = deco(self.fake_view)
        response = view(self.mock_request(True, '/target'))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/two_factor_auth?next=/target')

    @switches(TWOFACTOR=False)
    def test_decoration_no_params(self):
        # Needs two-factor authentication to be disabled so we get 'SUCCESS'
        # rather than a redirect.  Because of
        # https://github.com/disqus/gargoyle/issues/57, we cannot rely on the
        # switch being in any particular state, so we use a decorator.

        @sso_login_required
        def view(request, *args, **kwargs):
            return "SUCCESS"

        response = view(self.mock_request(True, '/target'))
        # if this works, the decorator handles this invocation properly
        self.assertEqual(response, 'SUCCESS')

    @switches(TWOFACTOR=False)
    def test_decoration_with_params(self):
        # Needs two-factor authentication to be disabled so we get 'SUCCESS'
        # rather than a redirect.  Because of
        # https://github.com/disqus/gargoyle/issues/57, we cannot rely on the
        # switch being in any particular state, so we use a decorator.

        @sso_login_required(login_url='/alt_login')
        def view(request, *args, **kwargs):
            return "SUCCESS"

        response = view(self.mock_request(True, '/target'))
        # if this works, the decorator handles this invocation properly
        self.assertEqual(response, 'SUCCESS')

    def test_require_twofactor_freshness_when_no_twofactor(self):
        response = view(self.mock_request(True, '/target'))
        self.assertEqual(response.status_code, 302)

    def test_require_twofactor_freshness_when_twofactor_old(self):
        # fake an old 2f session
        request = self.mock_request(True, '/target')
        request.session = {twofactor.TWOFACTOR_LOGIN: datetime(2000, 1, 1)}
        response = view(request)
        self.assertEqual(response.status_code, 302)

    def test_require_twofactor_freshness_when_twofactor_non_fresh(self):
        request = self.mock_request(True, '/target')
        delta = timedelta(0, settings.TWOFACTOR_FRESHNESS + 1)
        request.session = {
            twofactor.TWOFACTOR_LOGIN: datetime.utcnow() - delta}
        response = view(request)
        self.assertEqual(response.status_code, 302)

    def test_require_twofactor_freshness_when_twofactor_fresh(self):
        request = self.mock_request(True, '/target')
        twofactor.login(request)
        response = view(request)
        self.assertEqual(response, 'SUCCESS')


class SSOLoginRequiredInvalidatedEmailsTestCase(SSOBaseTestCase):

    def setUp(self):
        super(SSOLoginRequiredInvalidatedEmailsTestCase, self).setUp()
        self.calls = []

        @sso_login_required
        def view(request, *args, **kwargs):
            self.calls.append((request, args, kwargs))
            return "SUCCESS"

        self.account = self.factory.make_account()
        for email in self.account.emailaddress_set.all():
            email.invalidate()

        assert self.account.emailaddress_set.count() == 0
        assert self.account.invalidatedemailaddress_set.count() > 0

        self.request = Mock()
        self.request._messages = []
        self.request.user = self.account
        self.view = view

    def test_correct_template(self):
        response = self.view(self.request)
        self.assertEqual(
            response.template_name,
            'account/user_logged_out_no_valid_emails.html')

    def test_explanation_shown(self):
        response = self.view(self.request)
        response.render()
        msgs = (
            'You have no valid email addresses linked to your account',
            'To reactivate the account please contact our support team',
            settings.SUPPORT_FORM_URL,
        )
        for msg in msgs:
            self.assertIn(msg, response.content)
        self.assertNotIn(self.account.displayname, response.content)

    def test_logged_out(self):
        self.view(self.request)

        # the decorated view was not called
        self.assertEqual(self.calls, [])
        # user was logged out
        self.assertIsInstance(self.request.user, AnonymousUser)
        self.assertFalse(self.request.user.is_authenticated())


class SSOLoginRequiredNoEmailsTestCase(
        SSOLoginRequiredInvalidatedEmailsTestCase):

    def setUp(self):
        super(SSOLoginRequiredNoEmailsTestCase, self).setUp()
        self.account.emailaddress_set.all().delete()
        self.account.invalidatedemailaddress_set.all().delete()


class SSOLoginRequiredInvalidatedEmailsWarningTestCase(SSOBaseTestCase):

    def setUp(self):
        super(SSOLoginRequiredInvalidatedEmailsWarningTestCase, self).setUp()
        self.calls = []

        @sso_login_required
        def view(request, *args, **kwargs):
            self.calls.append((request, args, kwargs))
            return "SUCCESS"

        self.account = self.factory.make_account()
        self.invalid = self.factory.make_email_for_account(
            self.account, status=EmailStatus.NEW).invalidate()
        assert not self.invalid.account_notified

        assert self.account.emailaddress_set.count() == 1
        assert self.account.invalidatedemailaddress_set.count() == 1

        self.request = Mock()
        self.request.user = self.account
        self.view = view

        # patch messages framework to track messages
        self.mock_messages = self._apply_patch('webui.decorators.messages')

    def assert_view_called_once(self):
        # the decorated view was called once
        self.assertEqual(self.calls, [(self.request, (), {})])
        self.calls = []  # reset

    def assert_warning_shown_for_email(self, email):
        self.assert_view_called_once()
        # email is marked as notified
        invalid = InvalidatedEmailAddress.objects.get(id=email.id)
        self.assertTrue(invalid.account_notified)
        # message was shown
        self.mock_messages.warning.assert_called_with(
            self.request, EMAIL_INVALIDATED.format(email=invalid))

    def test_warning_shown(self):
        self.view(self.request)
        self.assert_warning_shown_for_email(email=self.invalid)

    def test_two_invalidated_emails(self):
        other = self.factory.make_email_for_account(
            self.account, status=EmailStatus.NEW).invalidate()
        assert self.account.invalidatedemailaddress_set.count() == 2

        # call the view for the first time
        self.view(self.request)

        # view was called and warning was shown for the older email
        self.assert_warning_shown_for_email(email=self.invalid)
        # the other email was unchanged
        unchanged = InvalidatedEmailAddress.objects.get(id=other.id)
        self.assertFalse(unchanged.account_notified)
        self.assertEqual(other, unchanged)

        # call the view again
        self.view(self.request)

        # the 'other' email has to be processed as a warning
        self.assert_warning_shown_for_email(email=other)

    def test_no_warning_shown_when_no_email(self):
        self.account.invalidatedemailaddress_set.all().delete()

        self.view(self.request)

        self.assert_view_called_once()
        # message was not shown
        self.assertFalse(self.mock_messages.warning.called)

    def test_warning_shown_only_if_account_not_notified_before(self):
        self.account.invalidatedemailaddress_set.update(account_notified=True)

        self.view(self.request)

        self.assert_view_called_once()
        # email is unchanged
        invalid = InvalidatedEmailAddress.objects.get(id=self.invalid.id)
        self.assertEqual(invalid, self.invalid)
        # message was not shown
        self.assertFalse(self.mock_messages.warning.called)


class RedirectHomeIfLoggedInTestCase(SSOBaseTestCase):

    def setUp(self):
        super(RedirectHomeIfLoggedInTestCase, self).setUp()
        self.request = Mock()

        @redirect_home_if_logged_in
        def view(request):
            return 'SUCCESS'
        self.view = view

    def test_decorator_with_logged_in_user(self):
        account = self.factory.make_account()
        self.request.user = account
        response = self.view(self.request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], reverse('account-index'))

    def test_decorator_with_anonymous_user(self):
        self.request.user = AnonymousUser()
        response = self.view(self.request)
        self.assertEqual(response, 'SUCCESS')
