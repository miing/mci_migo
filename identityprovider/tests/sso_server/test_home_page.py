from django.conf import settings

from identityprovider.models.account import Account
from identityprovider.models.openidmodels import OpenIDRPSummary
from identityprovider.tests.helpers import FunctionalTestCase


class HomePageTestCase(FunctionalTestCase):

    def test(self):
        # = Home Page =

        # When visiting the openid.launchpad.dev home page anonymously, the
        # user is presented with a login form:

        response = self.client.get(self.base_url)
        expected = "Log in to " + settings.BRAND_DESCRIPTION
        self.assertContains(response, expected)

        # However, if the user is logged in, they are presented with some
        # information about their account.
        response = self.login()
        title = self.title_from_response(response)
        self.assertEqual(title, "Sample Person's details")
        self.assertContains(response, "Full name")
        self.assertContains(response, "test@canonical.com")
        self.assertContains(response, "testing@canonical.com")
        self.assertContains(response, "Sites you last authenticated to")

        # == Previously Visited Sites ==

        # When the person is logged in and points his browser to
        # openid.launchpad.dev, he will also see a list containing up to 10
        # sites in which he authenticated recently, using the OpenID service.

        # Pretend the user authenticated to an OpenID relying party.
        OpenIDRPSummary.objects.record(
            Account.objects.get_by_email(self.default_email),
            'http://example.com/')

        # Now reload the page
        response = self.client.get(self.base_url)
        visited = self.get_from_response(response, '#visited-sites').text()
        self.assertIn("Sites you last authenticated to", visited)
        self.assertIn("Site", visited)
        self.assertIn("Last authenticated", visited)
        self.assertIn("http://example.com/", visited)
        self.assertIn("https://shop.canonical.com", visited)
        self.assertIn("2008-02-04", visited)

        # == Editing User Details ==

        # The user can edit their details from the main account page:
        data = dict(displayname="New name", password="TestPass23",
                    passwordconfirm="TestPass23", preferred_email=16)
        response = self.client.post(self.base_url, data=data, follow=True)
        title = self.title_from_response(response)
        self.assertEqual(title, "New name's details")

        # User can not use a blank display name:
        data['displayname'] = " "
        response = self.client.post(self.base_url, data=data, follow=True)
        self.assertContains(response, 'Required field')

        data['displayname'] = "Sample Person"
        response = self.client.post(self.base_url, data=data, follow=True)
        self.assertNotContains(response, 'Required field')

        # == Logging Out ==

        # From the Home page, the user can also log out:
        logout_link = self.get_attribute_from_response(
            response,
            'a#logout-link',
            'href')
        response = self.client.get(logout_link)
        title = self.title_from_response(response)
        self.assertEqual(title, "You have been logged out")

        # == Logging back in with new password ==

        # To log back in the user will have to use their new password:
        response = self.login(password='TestPass23')
        title = self.title_from_response(response)
        self.assertEqual(title, "Sample Person's details")
