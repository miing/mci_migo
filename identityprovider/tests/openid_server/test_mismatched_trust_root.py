from openid.message import IDENTIFIER_SELECT

from identityprovider.tests.helpers import OpenIDTestCase


class MismatchedTrustRootTestCase(OpenIDTestCase):

    def test(self):
        # = Mismatched Trust Roots =
        #
        # In a checkid OpenID request, the relying party sends
        # "openid.return_to" and "openid.trust_root" parameters.  The first is
        # a URL to return to on completion of the authentication dialogue.  The
        # second is a pattern that matches a prefix of the first parameter.
        #
        # For a relying party that uses multiple return_to URLs, the trust root
        # provides a way to identify all those requests as originating from a
        # single entity.
        #
        # This makes the trust root a good key to use if Launchpad is to
        # provide customised behaviour for certain known relying parties (such
        # as the Ubuntu shop).
        #
        # However, we can only use the trust root as a key if Launchpad
        # recognises and fails requests from hostile sites claiming to be from
        # a known trust root.  This is particularly important if we are
        # providing additional user information to the RP based on the trust
        # root.
        #
        # Let's try to make a checkid request using "https://shop.ubuntu.com/"
        # as a trust root but with a return URL from a different domain.  We
        # need to temporarily turn on error handling so that the
        # UntrustedReturnURL error gets converted to an OpenID response.

        trust_root = 'https://shop.ubuntu.com/'
        response = self.do_request(mode='checkid_setup', oid=IDENTIFIER_SELECT,
                                   **{'openid.trust_root': trust_root})

        self.assertContains(response, 'Consumer received GET')
        msg = "openid.error:return_to u'%s' not under trust_root u'%s'"
        self.assertContains(
            response, msg % (self.consumer_openid_url, trust_root))
        self.assertContains(response, 'openid.mode:error')

        # So provided that the trust roots we implement special handling for
        # are not overly broad, we can rely on the OpenID library to block
        # malicious requests.
