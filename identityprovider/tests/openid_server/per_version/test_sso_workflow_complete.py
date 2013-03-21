from django.conf import settings

from identityprovider.models.account import Account
from identityprovider.models.const import TokenType
from identityprovider.tests.helpers import OpenIDTestCase


class SSOWorkflowCompleteTestCase(OpenIDTestCase):

    def test(self):
        # = Launchpad Single-Signon Workflow: The whole process =

        # If a user wants to use a Launchpad-SSO web site, but does not have a
        # Launchpad account, they can register directly from the login page.

        # By doing so they will get an SSO account, but that it will have no
        # associated person as they're not actually using Launchpad (yet).

        # First we will set up the helper view that lets us test the final
        # portion of the authentication process:

        # The authentication process is started by the relying party issuing a
        # checkid_setup request, sending the user to Launchpad:
        response = self.do_openid_dance()

        # At this point, we are at the login page.  Let's create a new account
        # for an email address that has not been registered, also entering the
        # name and password:
        data = dict(
            displayname='New User', email=self.new_email,
            password='testP4ss', passwordconfirm='testP4ss',
        )
        link = self.get_attribute_from_response(
            response,
            'a[data-qa-id="_qa_create_account_link"]',
            'href')
        response = self.client.post(link, data=data, follow=True)

        title = self.get_from_response(response, 'h1.main').text()
        self.assertEqual(title, "Account creation mail sent")

        # Following the link sent by email will take the user to the page where
        # they confirm the registration.
        response = self.client.get(self.confirm_link(), follow=True)

        # It doesn't redirect:

        self.assertEqual(len(response.redirect_chain), 0)

        response = self.client.post(self.confirm_link(), follow=True)

        # Now the user is logged in with their new account, and has been
        # directed back to the original site:

        link_text = self.get_from_response(
            response, 'a[href="%s"]' % self.consumer_url)[0].text
        self.assertEqual(link_text, self.consumer_url)

        response = self.yes_to_decide(response)

        # And the response matches the new OpenID:
        account = Account.objects.get_by_email(self.new_email)
        expected_claimed_id = (
            self.base_url + '/+id/' + account.openid_identifier)

        info = self.complete_from_response(response, expected_claimed_id)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, expected_claimed_id)

        # Since this account was created using OpenID, we will not create an
        # entry in the Person table for it.
        self.assertTrue(account.person is None)

        # That account can obviously be used in further OpenID interactions.
        self.reset_client()

        response = self.do_openid_dance()
        response = self.login(response, email=self.new_email,
                              password='testP4ss')

        # Here we see the OpenID interaction completed successfully.
        link_text = self.get_from_response(
            response, 'a[href="%s"]' % self.consumer_url)[0].text
        self.assertEqual(link_text, self.consumer_url)

        response = self.yes_to_decide(response)
        info = self.complete_from_response(response, expected_claimed_id)

        self.assertEqual(info.status, 'success')

        # If the user forgets their password, it's possible to reset it.

        self.reset_client()
        response = self.do_openid_dance()

        link = self.get_attribute_from_response(
            response,
            'a[data-qa-id="_qa_forgot_password_link"]',
            'href')
        response = self.client.get(link)
        title = self.get_from_response(response, 'h1.main').text()
        reset_pwd_expected = "Reset your {0} password".format(
            settings.BRAND_DESCRIPTION)
        self.assertEqual(title, reset_pwd_expected)

        data = dict(email=self.new_email)
        response = self.client.post(link, data=data, follow=True)

        title = self.get_from_response(response, 'h1.main').text()
        self.assertEqual(title, "Forgotten your password?")

        form_action = self.get_from_response(response, 'form')[0].get('action')
        token = self._get_token(token_type=TokenType.PASSWORDRECOVERY,
                                email=self.new_email)
        data = dict(email=self.new_email, confirmation_code=token)
        response = self.client.post(form_action, data=data)

        last_redirect = response['Location']
        response = self.client.get(last_redirect)
        title = self.get_from_response(response, 'h1.main').text()
        self.assertEqual(title, reset_pwd_expected)

        data = dict(password='test2Mee', passwordconfirm='test2Mee')
        response = self.client.post(last_redirect, data=data, follow=True)

        # Here we see the OpenID interaction completed successfully.
        link_text = self.get_from_response(
            response, 'a[href="%s"]' % self.consumer_url)[0].text
        self.assertEqual(link_text, self.consumer_url)

        response = self.yes_to_decide(response)
        info = self.complete_from_response(response, expected_claimed_id)

        self.assertEqual(info.status, 'success')

        # And then log back in, using the new password.

        self.reset_client()
        response = self.do_openid_dance()

        response = self.login(response, email=self.new_email,
                              password='test2Mee')

        # Here we see the OpenID interaction completed successfully.
        link_text = self.get_from_response(
            response, 'a[href="%s"]' % self.consumer_url)[0].text
        self.assertEqual(link_text, self.consumer_url)

        response = self.yes_to_decide(response)
        info = self.complete_from_response(response, expected_claimed_id)

        self.assertEqual(info.status, 'success')
