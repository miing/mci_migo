# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
import urllib2

from django.test import TestCase

from identityprovider.models.person import Person
from identityprovider.utils import (
    canonical_url,
    http_request_with_timeout,
    password_policy_compliant,
    polite_form_errors,
    validate_launchpad_password,
)
from identityprovider.tests.utils import SSOBaseTestCase


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
