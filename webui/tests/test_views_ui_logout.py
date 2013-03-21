from django.test import TransactionTestCase
from django.conf import settings
from django.http import HttpResponse
from django.contrib.sessions.backends.cache import SessionStore

from identityprovider.models.openidmodels import OpenIDRPConfig
from identityprovider.models.const import AccountCreationRationale

from webui.views.ui import LogoutView


class LogoutViewTestCase(TransactionTestCase):

    def setUp(self):
        super(LogoutViewTestCase, self).setUp()
        self.view = LogoutView()
        self.cookies = {}

    def test_get_language_succeeds_when_user_has_attribute(self):
        self.preferredlanguage = "en"
        self.assertEqual(self.view.get_language(self), "en")
        del self.preferredlanguage

    def test_get_language_fails_when_user_has_no_attribute(self):
        self.assertEqual(self.view.get_language(object()), None)

    def set_cookie(self, cookie_name, cookie_value):
        self.cookies[cookie_name] = cookie_value

    def test_set_language_with_language_equal_to_none(self):
        self.view.set_language(self, None)
        self.assertEqual(self.cookies, {})

    def test_set_language_with_language_equal_to_en(self):
        self.view.set_language(self, "en")
        self.assertEqual(self.cookies[settings.LANGUAGE_COOKIE_NAME], "en")

    def test_set_orequest_when_token_and_orequset_is_passed(self):
        session = {}
        self.view.set_orequest(session, 'token', 'orequest')
        self.assertEqual(session['token'], 'orequest')

    def test_set_orequest_when_token_is_none(self):
        session = {}
        self.view.set_orequest(session, None, 'orequest')
        self.assertFalse('orequest' in session.values())

    def test_set_orequest_when_orequest_is_none(self):
        session = {}
        self.view.set_orequest(session, 'toekn', None)
        self.assertFalse('token' in session)

    def create_openid_rp_config(self, trust_root):
        OpenIDRPConfig.objects.create(
            trust_root=trust_root,
            displayname="Example",
            creation_rationale=AccountCreationRationale.UNKNOWN)

    def test_get_return_to_root_url(self):
        trust_root = 'http://example.com/'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url(trust_root, None)
        self.assertEqual(return_to, trust_root)

    def test_get_return_to_url_without_referer_and_url_is_recognized(self):
        trust_root = 'http://example.com/r'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url(trust_root, None)
        self.assertEqual(return_to, trust_root)

    def test_get_return_to_url_when_extends_root(self):
        trust_root = 'http://example.com/r'
        logout = trust_root + '/a'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url(logout, None)
        self.assertEqual(return_to, logout)

    def test_get_return_to_url_when_diminishes_root(self):
        logout = 'http://example.com/r'
        trust_root = logout + '/a'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url(logout, None)
        self.assertTrue(return_to is None)

    def test_get_return_to_url_when_tricky_trust(self):
        trust_root = 'http://%.example.com/r'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url(
            'http://launchpad.net/?sneaky=.example.com/r', None)
        self.assertTrue(return_to is None)

    def test_get_return_to_url_when_tricky_return(self):
        trust_root = 'http://example.com/r'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url('http://%.com/r', None)
        self.assertTrue(return_to is None)

    def test_get_return_to_url_when_tilde(self):
        trust_root = 'http://example.com/~id'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url(trust_root, None)
        self.assertEqual(return_to, trust_root)

    def test_get_return_to_url_when_referer_matches_known_url(self):
        trust_root = 'http://example.com/test/'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url(trust_root, trust_root)
        self.assertEqual(return_to, trust_root)

    def test_get_return_to_url_when_referer_extends_known_url(self):
        trust_root = 'http://example.com/test/'
        referer = trust_root + 'again/'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url(trust_root, referer)
        self.assertEqual(return_to, trust_root)

    def test_get_return_to_url_referer_extends_known_url_different_trust_root(
            self):
        trust_root = 'http://example.com/test/'
        requested_url = trust_root + 'me/'
        referer = trust_root + 'again/'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url(requested_url, referer)
        self.assertEqual(return_to, requested_url)

    def test_get_return_to_url_when_referer_diminishes_known_url(self):
        referer = 'http://example.com/'
        trust_root = referer + 'test/'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url(trust_root, referer)
        self.assertTrue(return_to is None)

    def test_get_return_to_url_when_referer_mismatches_known_url(self):
        trust_root = 'http://example.com/r'
        referer = 'http://r.example.com'
        self.create_openid_rp_config(trust_root)
        return_to = self.view.get_return_to_url(trust_root, referer)
        self.assertTrue(return_to is None)

    def test_get_return_to_url_when_url_is_unknown(self):
        return_to = self.view.get_return_to_url('http://unknown.example.com',
                                                None)
        self.assertTrue(return_to is None)

    def test_get_return_to_url_when_return_to_is_none(self):
        return_to = self.view.get_return_to_url(None, None)

        self.assertTrue(return_to is None)

    def test_get_site_name_with_valid_return_to(self):
        trust_root = 'http://example.com/'
        self.create_openid_rp_config(trust_root)
        site_name = self.view.get_site_name(trust_root)
        self.assertEqual(site_name, "Example")

    def test_get_site_name_with_invalid_return_to(self):
        trust_root = 'http://example.com/'
        self.create_openid_rp_config(trust_root)
        site_name = self.view.get_site_name('http://notvalid.com/')
        self.assertTrue(site_name is None)

    def sites_with_active_sessions(self):
        return []

    def test_call(self):
        """
        Sanity check test, make sure that all code in __call__ is runable.
        """
        self.user = self
        self.session = SessionStore()
        self.GET = {}
        self.META = {}
        response = self.view(self, None)

        self.assertTrue(isinstance(response, HttpResponse))
