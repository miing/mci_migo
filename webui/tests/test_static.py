# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import (
    patch_settings,
    SSOBaseTestCase,
)


class DummyRequest(object):
    META = {}


class UbuntuBrandingTestCase(SSOBaseTestCase):
    fixtures = ["test"]
    brand = 'ubuntu'
    brand_desc = 'Ubuntu Single Sign On'

    def setUp(self):
        super(UbuntuBrandingTestCase, self).setUp()
        brand_patch = patch_settings(
            BRAND=self.brand,
            BRAND_DESCRIPTIONS={self.brand: self.brand_desc},
        )
        brand_patch.start()
        self.addCleanup(brand_patch.stop)

        self.login_message = "This is " + self.brand_desc

    def assertAvailable(self, url, text):
        r = self.client.get(url)
        self.assertContains(r, text)

    def assertNotAvailable(self, url):
        r = self.client.get(url)
        self.assertEqual(r.status_code, 404)

    def test_openid(self):
        r = self.client.get('/+openid')
        self.assertContains(r, self.login_message)

    def test_faq_page(self):
        self.assertAvailable('/+faq', "Frequently asked questions")

    def test_description_page(self):
        self.assertAvailable('/+description', "What's this?")

    def test_applications_page(self):
        self.client.login(username='mark@example.com',
                          password=DEFAULT_USER_PASSWORD)
        self.assertAvailable('/+applications', 'Applications you use')

    def test_logout(self):
        self.client.login(username='test@canonical.com',
                          password=DEFAULT_USER_PASSWORD)
        self.assertAvailable('/', '_qa_edit_account')

        # Then we log out
        response = self.client.get('/+logout')
        # and verify the logout works
        self.assertContains(response, 'You have been logged out')


class LaunchpadBrandingTestCase(UbuntuBrandingTestCase):
    brand = 'launchpad'
    brand_desc = 'Launchpad Login Service'

    def test_faq_page(self):
        self.assertNotAvailable('/+faq')

    def test_description_page(self):
        self.assertNotAvailable('/+description')

    def test_applications_page(self):
        self.client.login(username='mark@example.com',
                          password=DEFAULT_USER_PASSWORD)
        self.assertNotAvailable('/+applications')


class UbuntuOneBrandingTestCase(UbuntuBrandingTestCase):
    brand = 'ubuntuone'
    brand_desc = 'Ubuntu One'
