from identityprovider.tests.helpers import OpenIDTestCase


class RefererCookieTestCase(OpenIDTestCase):

    def test(self):
        # = Recording the Referer in a Cookie =

        # In order to maintain reasonable quality of service for important RPs,
        # we need some way that the load balancer can categorise connections by
        # the RP they originate from.

        # The first request in the OpenID authentication process can easily be
        # categorised by looking at the "Referer" request header, but that
        # can't be done for subsequent requests (whose "Referer" header will
        # point at the OpenID provider).

        # To solve this problem, we set a cookie at the beginning of the
        # authentication request containing the referer value.  The load
        # balancer can then use this to classify the subsequent requests.

        # Now when we start the OpenID authentication request, the "Referer"
        # header gets saved into a cookie.  The cookie has no expiry date set,
        # so will not last beyond the current web client session.

        self.do_openid_dance(HTTP_REFERER='http://example.com/referer')
        self.assertEqual(self.client.cookies['openid_referer'].value,
                         'http://example.com/referer')
