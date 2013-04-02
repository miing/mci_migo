# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.conf import settings
from django.core.urlresolvers import reverse

from identityprovider.tests.utils import SSOBaseTestCase, patch_settings


class TestingViewsDisabledTestCase(SSOBaseTestCase):

    testing = False

    def setUp(self):
        super(TestingViewsDisabledTestCase, self).setUp()
        # ensure that DEBUG does not interfere with the TESTING views
        p = patch_settings(DEBUG=False, TESTING=self.testing)
        p.start()
        self.addCleanup(p.stop)

        assert getattr(settings, 'TESTING') == self.testing

    def get_delegate_profile(self):
        p = self.factory.make_person(name='foo')
        url = reverse('testing-delegate-profile', kwargs=dict(username=p.name))
        return self.client.get(url)

    def test_error(self):
        response = self.client.get(reverse('testing-error'))
        self.assertEqual(response.status_code, 404)

    def test_delegate_profile_user_does_not_exist(self):
        url = reverse('testing-delegate-profile', kwargs=dict(username='bar'))
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_delegate_profile_user_exists(self):
        response = self.get_delegate_profile()
        self.assertEqual(response.status_code, 404)

    def test_openid_consumer(self):
        response = self.client.get(reverse('testing-openid-consumer'))
        self.assertEqual(response.status_code, 404)


class TestingViewsEnabledTestCase(TestingViewsDisabledTestCase):

    testing = True

    def test_error(self):
        self.assertRaises(FloatingPointError, self.client.get,
                          reverse('testing-error'))

    def test_delegate_profile_user_exists(self):
        response = self.get_delegate_profile()
        self.assertContains(response, 'Test delegation profile for: ~foo')
        self.assertContains(response, 'Test profile for ~foo')

    def test_openid_consumer(self):
        response = self.client.get(reverse('testing-openid-consumer'))
        self.assertContains(response, 'Consumer received GET')
