from urlparse import urljoin

from django.conf import settings
from django.test import TestCase

from lazr.restfulclient.resource import ServiceRoot
from u1testutils import mail

from identityprovider.tests.api.helpers import EmailScraper


class RegisterTestCase(TestCase):
    def make_api(self, base_url=None):
        if base_url is None:
            base_url = settings.SSO_ROOT_URL
        self.base_url = base_url
        self.api = ServiceRoot(None, urljoin(base_url, "/api/1.0"))

    def test_register_with_mobile_platform(self):
        self.make_api()
        # 1. call api.registrations.register
        email = mail.make_unique_test_email_address()
        data = {
            'email': email,
            'password': 'TestPassword1',
            'displayname': 'Test User',
            'captcha_id': 'bogus',
            'captcha_solution': 'skip it',
            'platform': 'mobile',
        }
        response = self.api.registrations.register(**data)
        self.assertEqual(response['status'], 'ok')
        self.assertEqual(response['message'], 'Email verification required.')

        # 2. get the confirmation email
        scraper = EmailScraper()
        link = scraper.get_account_validation_link(email)

        # 3. verify email includes link
        self.assertTrue(link.startswith(self.base_url))
        self.assertTrue(link.endswith(email))
