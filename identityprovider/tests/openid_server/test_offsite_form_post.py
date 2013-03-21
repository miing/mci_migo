from identityprovider.tests.helpers import OpenIDTestCase


class OffsiteFormPostTestCase(OpenIDTestCase):

    def test(self):
        # == Posts to the OpenID endpoint ==
        #
        # The OpenID 2.0 protocol allows authentication requests to be made via
        # form posts.  Such requests appear to be off-site form posts.  We
        # explicitly allow POST requests through to the OpenID endpoint:

        response = self.client.get(
            '/+openid', data={'openid.mode': 'no-such-method'},
            HTTP_REFERER='http://relying-party.com/')

        self.assertContains(response, "no-such-method")
        self.assertContains(response, 'mode:error')
