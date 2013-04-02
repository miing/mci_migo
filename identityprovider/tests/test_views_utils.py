# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.core import urlresolvers
from django.http import Http404
from django.test import TestCase

from mock import patch, Mock

from identityprovider.models import OpenIDRPConfig
from identityprovider.views import utils
from identityprovider.tests.utils import patch_settings


class IsSafeRedirectTestCase(TestCase):

    def test_is_safe_redirect_url_return_false(self):
        self.assertFalse(utils.is_safe_redirect_url('non-existing'))

    def test_is_safe_redirect_url_with_params(self):
        self.assertFalse(
            utils.is_safe_redirect_url('non-existing?q=some_value'))

    @patch('identityprovider.views.utils.urlresolvers.resolve')
    def test_is_safe_redirect_url_404(self, mock_resolve):
        mock_resolve.side_effect = urlresolvers.Resolver404()

        self.assertFalse(utils.is_safe_redirect_url('non-existing'))


class GetRPConfigTestCase(TestCase):
    trust_root1 = 'http://zaraza.bu/'
    trust_root2 = 'http://zaraza.bu'

    def test_get_rpconfig_with_trailing_slash(self):
        expected_rpconfig = OpenIDRPConfig.objects.create(
            trust_root=self.trust_root1)

        rpconfig = utils.get_rpconfig(self.trust_root1)
        self.assertEqual(rpconfig, expected_rpconfig)

        rpconfig = utils.get_rpconfig(self.trust_root2)
        self.assertEqual(rpconfig, expected_rpconfig)

    def test_get_rpconfig_without_trailing_slash(self):
        expected_rpconfig = OpenIDRPConfig.objects.create(
            trust_root=self.trust_root2)

        rpconfig = utils.get_rpconfig(self.trust_root1)
        self.assertEqual(rpconfig, expected_rpconfig)

        rpconfig = utils.get_rpconfig(self.trust_root2)
        self.assertEqual(rpconfig, expected_rpconfig)

    def test_get_rpconfig_partial_match_longer(self):
        OpenIDRPConfig.objects.create(trust_root=self.trust_root1)
        rpconfig = utils.get_rpconfig(self.trust_root1 + 'some/extra/url/')
        self.assertEqual(rpconfig, None)

    def test_get_rpconfig_partial_match_shorter(self):
        OpenIDRPConfig.objects.create(
            trust_root=self.trust_root1 + 'some/extra/url/')
        rpconfig = utils.get_rpconfig(self.trust_root1)
        self.assertEqual(rpconfig, None)


class RequireTestingEnabledTestCase(TestCase):
    @staticmethod
    def view(request):
        return 'SUCCESS'

    def test_decorator_with_testing_enabled(self):
        request = Mock()
        with patch_settings(TESTING=True):
            decorated = utils.require_testing_enabled(self.view)
            response = decorated(request)
            self.assertEqual(response, 'SUCCESS')

    def test_decorator_with_testing_disabled(self):
        request = Mock()
        with patch_settings(TESTING=False):
            decorated = utils.require_testing_enabled(self.view)
            with self.assertRaises(Http404):
                decorated(request)
