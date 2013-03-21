from identityprovider.tests.helpers import FunctionalTestCase


class LicenseTestCase(FunctionalTestCase):

    def test(self):
        response = self.client.get(self.base_url)
        # Make sure we're linking to Launchpad project
        self.assertContains(
            response, 'https://launchpad.net/canonical-identity-provider')
        # We should also link the the text of the license directly.
        self.assertContains(
            response, 'http://www.gnu.org/licenses/agpl-3.0.html')
