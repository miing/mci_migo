# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
import urllib2

from django.conf import settings
from django.test import TestCase
from gargoyle.testutils import switches
from mock import patch

from identityprovider.models.person import Person
from identityprovider.utils import (
    canonical_url,
    http_request_with_timeout,
    password_policy_compliant,
    polite_form_errors,
    redirection_url_for_token,
    validate_launchpad_password,
)
from identityprovider.tests.utils import (
    patch_settings,
    SSOBaseTestCase,
)
from identityprovider.utils import get_current_brand


class CanonicalUrlTestCase(SSOBaseTestCase):

    def test_when_object_is_not_person(self):
        self.assertTrue(canonical_url(None) is None)

    def test_when_view_name_is_none(self):
        url = canonical_url(Person(name="test"), view_name=None)
        self.assertEqual(url, "https://launchpad.net/~test")

    def test_when_view_name_is_not_none(self):
        url = canonical_url(Person(name="test"), view_name="TEST")
        self.assertEqual(url, "https://launchpad.net/~test/TEST")


class PasswordPolicyCompliantTestCase(SSOBaseTestCase):

    def test_when_password_is_to_short(self):
        self.assertFalse(password_policy_compliant('a'))


class PoliteFormErrorsTestCase(SSOBaseTestCase):

    def test_polite_errors(self):
        text = "Enter a valid e-mail address."
        errors = {'email': [text]}

        polite_form_errors(errors)

        self.assertTrue(errors['email'][0] != text)


class ValidateLaunchpadPasswordTestCase(SSOBaseTestCase):

    def test_when_there_is_binascii_error_is_raised(self):
        self.assertFalse(validate_launchpad_password('a', 'b'))


class HttpRequestWithTimeoutTestCase(TestCase):

    def setUp(self):
        super(HttpRequestWithTimeoutTestCase, self).setUp()
        self.exception = None
        self.output = None
        self.headers = None

        class MockDatafile(object):

            def __init__(self, output, headers):
                self.output = output
                self.headers = headers

            def read(self):
                return self.output

            def info(self):
                return self.headers

        def mock_urlopen(request):
            self.request = request
            if self.exception:
                raise urllib2.URLError("arg")
            return MockDatafile(self.output, self.headers)

        self.urlopen = urllib2.urlopen
        urllib2.urlopen = mock_urlopen

    def tearDown(self):
        urllib2.urlopen = self.urlopen

    def test_without_data_and_successful_outcome(self):
        self.output = "output"
        data, headers = http_request_with_timeout("http://example.com")

        self.assertEqual(data, "output")

    def test_without_data_and_failing(self):
        self.exception = True
        data, headers = http_request_with_timeout("http://example.com")
        self.assertEqual(data, None)

    def test_with_data_and_successful_outcome(self):
        self.output = "output"
        data, headers = http_request_with_timeout("http://example.com",
                                                  {"i1": "v1", "i2": "v2"})
        self.assertTrue("&" in self.request.data)


class GetCurrentBrandTestCase(TestCase):
    def test_defaults_to_ubuntu_brand(self):
        with patch_settings(BRAND=None):
            brand = get_current_brand()

        self.assertEqual('ubuntu', brand)

    def test_no_switch_but_brand_setting_lp(self):
        with patch_settings(BRAND='launchpad'):
            brand = get_current_brand()

        self.assertEqual('launchpad', brand)

    @switches(BRAND_UBUNTUONE=True)
    def test_feature_switch_for_u1(self):
        brand = get_current_brand()

        self.assertEqual('ubuntuone', brand)

    @switches(BRAND_LAUNCHPAD=True)
    def test_feature_switch_for_lp(self):
        brand = get_current_brand()

        self.assertEqual('launchpad', brand)

    @switches(BRAND_UBUNTUONE=True)
    def test_feature_switch_for_u1_ignored(self):
        with patch_settings(BRAND='launchpad'):
            brand = get_current_brand()

        self.assertEqual('launchpad', brand)

    @switches(BRAND_LAUNCHPAD=True)
    def test_feature_switch_for_lp_ignored(self):
        with patch_settings(BRAND='ubuntuone'):
            brand = get_current_brand()

        self.assertEqual('ubuntuone', brand)

    def get_is_active_mock(self):
        patcher = patch('gargoyle.gargoyle.is_active')
        self.addCleanup(patcher.stop)
        return patcher.start()

    def test_default_on_error(self):
        """Any exception during get_current_brand results in default."""
        mock_is_active = self.get_is_active_mock()
        mock_is_active.side_effect = Exception('bang')

        with patch.multiple(settings, BRAND='ubuntu'):
            brand = get_current_brand()

        self.assertEqual('ubuntu', brand)


class RedirectionURLForTokenTestCase(SSOBaseTestCase):

    def test_if_token_is_none(self):
        url = redirection_url_for_token(None)
        self.assertEqual(url, "/")

    def test_if_token_is_not_none(self):
        token = "ABCDEFGH" * 2
        url = redirection_url_for_token(token)
        self.assertEqual(url, "/%s/+decide" % token)
