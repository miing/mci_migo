from datetime import datetime, timedelta

from django.conf import settings
from django.test.client import RequestFactory
from django.utils import unittest
from mock import Mock, patch

from identityprovider.models.twofactor import (
    TWOFACTOR_LOGIN,
    is_authenticated,
    is_fresh,
    is_twofactor_enabled,
    is_upgraded,
    login,
    logout,
    site_requires_twofactor_auth,
)


class TwoFactorTestCase(unittest.TestCase):

    def setUp(self):
        super(TwoFactorTestCase, self).setUp()
        self.request = RequestFactory().get('/')
        self.request.user = Mock()
        self.request.user.is_authenticated.return_value = True
        self.request.session = {}

    @patch('identityprovider.models.twofactor.datetime')
    def test_login_sets_session(self, mock_datetime):
        mock_datetime.utcnow.return_value = datetime(2012, 04, 01)
        login(self.request)
        self.assertEqual(self.request.session[TWOFACTOR_LOGIN],
                         mock_datetime.utcnow.return_value)

    def test_logout_clears_sessiosn(self):
        login(self.request)

        logout(self.request)
        self.assertFalse(TWOFACTOR_LOGIN in self.request.session)

    def test_is_fresh_when_no_twofactor(self):
        self.assertFalse(is_fresh(self.request))

    def test_is_fresh_when_twofactor(self):
        login(self.request)
        self.assertTrue(is_fresh(self.request))

    def test_is_fresh_with_old_session(self):
        login(self.request)
        # fake old session
        self.request.session[TWOFACTOR_LOGIN] -= timedelta(
            0, settings.TWOFACTOR_FRESHNESS + 1)
        self.assertFalse(is_fresh(self.request))

    def test_is_upgraded_when_no_twofactor(self):
        self.assertFalse(is_upgraded(self.request))

    def test_is_upgraded_when_twofactor(self):
        login(self.request)
        self.assertTrue(is_upgraded(self.request))

    def test_is_upgraded_with_old_session(self):
        login(self.request)
        # fake old session
        self.request.session[TWOFACTOR_LOGIN] -= timedelta(
            0, settings.TWOFACTOR_TTL)
        self.assertFalse(is_upgraded(self.request))

    def test_is_authenticated_anonymous(self):
        self.request.user.is_authenticated.return_value = False
        self.assertFalse(is_authenticated(self.request))

    def test_is_authenticated_twofactor_disabled(self):
        name = 'identityprovider.models.twofactor.is_twofactor_enabled'
        with patch(name) as mock_enabled:
            mock_enabled.return_value = False
            self.assertTrue(is_authenticated(self.request))

    def test_is_authenticated_twofactor_not_required(self):
        name = 'identityprovider.models.twofactor.is_twofactor_enabled'
        with patch(name) as mock_enabled:
            mock_enabled.return_value = True
            self.request.user.twofactor_required = False
            self.assertTrue(is_authenticated(self.request))

    def test_is_authenticated_and_upgraded(self):
        base = 'identityprovider.models.twofactor.'
        name = base + 'is_twofactor_enabled'
        with patch(name) as mock_enabled:
            mock_enabled.return_value = True
            self.request.user.twofactor_required = True
            name = base + 'is_upgraded'
            with patch(name) as mock_upgraded:
                self.assertEqual(is_authenticated(self.request),
                                 mock_upgraded.return_value)

    @patch('identityprovider.models.twofactor.is_twofactor_enabled')
    def test_site_requires_twofactor_auth_with_twofactor_disabled(
            self, mock_enabled):

        mock_enabled.return_value = False
        rpconfig = Mock()
        rpconfig.twofactor_required.return_value = True

        required = site_requires_twofactor_auth(self.request, None, rpconfig)
        self.assertFalse(required)

    @patch('identityprovider.models.twofactor.is_twofactor_enabled')
    def test_site_requires_twofactor_auth_with_twofactor_enabled_no_rpconfig(
            self, mock_enabled):

        mock_enabled.return_value = False

        required = site_requires_twofactor_auth(self.request, None, None)
        self.assertFalse(required)

    @patch('identityprovider.models.twofactor.is_twofactor_enabled')
    def test_site_requires_twofactor_auth_with_twofactor_enabled(
            self, mock_enabled):

        mock_enabled.return_value = True
        rpconfig = Mock()
        rpconfig.twofactor_required.return_value = True

        required = site_requires_twofactor_auth(self.request, None, rpconfig)
        self.assertTrue(required)

    def test_is_twofactor_enabled_in_readonly_mode(self):
        with patch.multiple(settings, READ_ONLY_MODE=True):
            self.assertFalse(is_twofactor_enabled(self.request))

    @patch('identityprovider.models.twofactor.gargoyle.is_active')
    def test_is_twofactor_enabled_in_readwrite_mode(self, mock_is_active):
        with patch.multiple(settings, READ_ONLY_MODE=False):
            enabled = is_twofactor_enabled(self.request)
            self.assertEqual(enabled, mock_is_active.return_value)
