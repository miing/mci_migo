from identityprovider.tests.helpers import OpenIDTestCase


class SSOAutoAuthorizeTestCase(OpenIDTestCase):

    def test(self):
        # = Single-Signon Workflow: Automatic Authorization =

        # For sites that are intended to look like an integrated part of
        # Canonical's single sign on system, we would like to avoid actively
        # asking the user to authenticate to the site.

        # As the user is likely to consider the sites to be part of a single
        # larger system, it just causes confusion.

        # First we will set up the helper view that lets us test the final
        # portion of the authentication process:

        # Next we'll set up the trust root we're using to have its requests
        # automatically authorized:

        self.create_openid_rp_config(auto_authorize=True)

        # If we are not logged in, automatically authorized sites act the same
        # as normal ones, and the user is presented with the login page:

        response = self.do_openid_dance()
        title = self.title_from_response(response)
        self.assertEqual(title, "Log in")

        # When the user logs in, he will be directed back to the relying party
        # without requesting for authorization as the trust root has automatic
        # authorization enabled.
        response = self.login(response)
        info = self.complete_from_response(response, self.claimed_id)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, self.claimed_id)

        # If the user is already logged in, he will be directed back to the
        # relying party immediately.

        response = self.do_openid_dance()
        info = self.complete_from_response(response, self.claimed_id)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, self.claimed_id)
