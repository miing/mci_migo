from identityprovider.tests.helpers import OpenIDTestCase
from time import strftime


class CopyrightTestCase(OpenIDTestCase):

    def test(self):
        response = self.client.get(self.base_url)
        copyright = self.get_from_response(response, '#copyright')
        self.assertIn(
            u'\xa9 2009-%s Canonical Ltd.' % strftime('%Y'),
            copyright.text())
