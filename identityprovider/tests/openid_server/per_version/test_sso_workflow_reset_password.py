from identityprovider.tests.helpers import OpenIDTestCase


class SSOWorkflowResetPasswordTestCase(OpenIDTestCase):

    def test_unregistered_email(self):
        # = Launchpad Single-Signon Workflow: Password Reset =

        # If a user wants to use a Launchpad-SSO web site, but has forgotten
        # their password, they can ask for it to be emailed to them from the
        # login page.

        # First we will set up the helper view that lets us test the final
        # portion of the authentication process:

        # The authentication process is started by the relying party issuing a
        # checkid_setup request, sending the user to Launchpad:
        response = self.do_openid_dance()

        # At this point, we are at the login page.  Lets try to recover a
        # password for an unregistered email. This shouldn't result in an
        # error, because we don't want to reveal (non-)existing email
        # addresses:
        link = self.get_attribute_from_response(
            response,
            'a[data-qa-id="_qa_forgot_password_link"]',
            'href')
        data = dict(email='no-account@example.com')
        response = self.client.post(link, data=data, follow=True)

        title = self.get_from_response(response, 'h1.main').text()
        self.assertEqual(title, "Forgotten your password?")

    def test_email_for_team(self):
        # If the user tries to recover a password registered to a team, that
        # wouldn't fail either:
        response = self.do_openid_dance()

        link = self.get_attribute_from_response(
            response,
            'a[data-qa-id="_qa_forgot_password_link"]',
            'href')
        data = dict(email='support@ubuntu.com')
        response = self.client.post(link, data=data, follow=True)

        title = self.get_from_response(response, 'h1.main').text()
        self.assertEqual(title, "Forgotten your password?")

    def test_valid_email(self):
        # Finally, lets try and recover the password for a test@canonical.com:

        response = self.do_openid_dance()
        link = self.get_attribute_from_response(
            response,
            'a[data-qa-id="_qa_forgot_password_link"]',
            'href')
        data = dict(email=self.default_email)
        response = self.client.post(link, data=data, follow=True)

        title = self.get_from_response(response, 'h1.main').text()
        self.assertEqual(title, "Forgotten your password?")

        # The user would then check their email, and find a message.
        # Let's extract the URL from the email and follow the link:

        link = self.recover_link(email=self.default_email)
        response = self.client.get(link, follow=True)
        link = response.redirect_chain[-1][0]
        url_re = self.base_url + '/token/.*?/\+resetpassword/'
        self.assertRegexpMatches(link, url_re + self.default_email)

        # The user can now enter a new password:

        data = dict(password='new Passw0rd', passwordconfirm='new Passw0rd')
        response = self.client.post(link, data=data, follow=True)

        # Now the user is logged in, and has been directed back to the original
        # site:
        link_text = self.get_from_response(
            response, 'a[href="%s"]' % self.consumer_url)[0].text
        self.assertEqual(link_text, self.consumer_url)

        response = self.yes_to_decide(response)
        claimed_id = self.base_url + '/+id/name12_oid'
        info = self.complete_from_response(response, claimed_id)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, claimed_id)
