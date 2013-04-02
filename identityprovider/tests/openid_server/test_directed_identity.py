from openid.message import IDENTIFIER_SELECT

from identityprovider.tests.helpers import OpenIDTestCase


class DirectedIdentityTestCase(OpenIDTestCase):

    def test(self):
        self.create_openid_rp_config(auto_authorize=False)

        # Our OpenID 1.1 implementation supports the OpenID 2.0 feature where
        # the consumer need not specify the identity URL, instead leaving it up
        # to the OpenID provider to determine it. We call this mode 'OP
        # Identifier' for lack of a better name.
        #
        # To do this, the consumer simply needs to specify the identity as
        # 'http://specs.openid.net/auth/2.0/identifier_select'.  Starting with
        # a new browser context, we are presented with a login screen.  After
        # authenticating to Launchpad, we return to the consumer:
        #
        # If authorization is successful, the consumer can determine the actual
        # identity from the response and do further validation as normal.

        response = self.do_request(mode='checkid_setup', oid=IDENTIFIER_SELECT,
                                   with_assoc_handle=False)
        title = self.title_from_response(response)
        self.assertEqual(title, "Log in")

        response = self.login(response)
        response = self.yes_to_decide(response)

        self.assertContains(response, 'Consumer received GET')
        self.assertContains(
            response, 'openid.identity:' + self.claimed_id)
        self.assertContains(response, 'openid.mode:id_res')
        self.assertContains(response, 'openid.return_to:' + self.consumer_url)

        # If we happened to be logged into SSO previously, we would be
        # presented with an authorization screen instead:

        response = self.do_request(mode='checkid_setup', oid=IDENTIFIER_SELECT,
                                   with_assoc_handle=False)
        title = self.title_from_response(response)
        self.assertEqual(title, 'Authenticate to ' + self.consumer_url)

        response = self.yes_to_decide(response)
        self.assertContains(response, 'Consumer received GET')
        self.assertContains(
            response, 'openid.identity:' + self.claimed_id)
        self.assertContains(response, 'openid.mode:id_res')
        self.assertContains(
            response, 'openid.return_to:' + self.consumer_openid_url)
