from django.test import TestCase
from django.test.client import RequestFactory
from mock import patch

from identityprovider import context_processors
from identityprovider.tests.utils import patch_settings


class DebugTestCase(TestCase):

    def setUp(self):
        super(DebugTestCase, self).setUp()
        p = patch('identityprovider.context_processors.'
                  'context_processors.debug')
        self.mock_debug = p.start()
        self.addCleanup(p.stop)

    def test_result_no_request(self):
        request = None
        expected = {}
        self.mock_debug.side_effect = AttributeError()

        actual = context_processors.debug(request)

        self.assertEqual(actual, expected)
        self.mock_debug.assert_called_once_with(request)

    def test_result_with_request(self):
        request = RequestFactory().get('')
        expected = dict(foo='bar', zaraza=object())
        self.mock_debug.return_value = expected

        actual = context_processors.debug(request)

        self.assertEqual(actual, expected)
        self.mock_debug.assert_called_once_with(request)


class BrandingTestCase(TestCase):

    def assert_result(self, request):
        expected = dict(
            brand='zaraza',
            brand_description='Lorem Ipsum',
        )
        with patch_settings(
                BRAND=expected['brand'],
                BRAND_DESCRIPTIONS=dict(
                    zaraza=expected['brand_description'])):
            actual = context_processors.branding(request)

        self.assertEqual(actual, expected)

    def test_result_no_request(self):
        self.assert_result(None)

    def test_result_with_request(self):
        request = RequestFactory().get('')
        self.assert_result(request)

    def test_no_description(self):
        with patch_settings(
                BRAND='zaraza', BRAND_DESCRIPTIONS={}):
            result = context_processors.branding(None)

        self.assertEqual('zaraza', result['brand'])
        self.assertEqual('', result['brand_description'])
