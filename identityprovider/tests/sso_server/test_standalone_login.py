from django.conf import settings
from django.core.urlresolvers import reverse

from identityprovider.models.account import Account
from identityprovider.models.const import TokenType
from identityprovider.tests.helpers import FunctionalTestCase


class StandaloneLoginTestCase(FunctionalTestCase):

    def test_login(self):
        """Logging into the base url without an OpenID request.

        We allow users accessing the base url directly (instead of
        being sent there from an OpenID RP) to login, so that they can
        see/change their details.

        """
        response = self.client.get(self.base_url)
        content = self.get_from_response(response, '#content').text()
        self.assertIn("Log in to " + settings.BRAND_DESCRIPTION, content)
        self.assertIn("_qa_create_account_link", response.content)

        response = self.login()
        # Once successfully logged in, they will see the details of their
        # account.
        self.assertContains(response, "Full name")
        self.assertContains(response, self.default_email)

    def test_register(self, reset_client=False):
        """Creating a new account."""
        url = reverse('new_account')
        self.client.get(url)  # set cookie
        data = dict(
            displayname='New User', email=self.new_email,
            password='testP4ss', passwordconfirm='testP4ss',
        )
        response = self.client.post(url, data=data, follow=True)
        self.assertContains(response, "Account creation mail sent")

        link = self.confirm_link()

        if reset_client:
            # Try to confirm the new account from out of the original session.
            self.reset_client()

        response = self.client.get(link)
        self.assertContains(
            response, '_qa_confirm_new_account')
        msg = 'The account for %s is ready to be created.' % self.new_email
        self.assertContains(response, msg)

        # Finish the registration process.
        response = self.client.post(link)
        self.assertRedirects(response, reverse('account-index'))

        account = Account.objects.get_by_email(email=self.new_email)
        self.assertEqual(account.displayname, 'New User')
        self.assertTrue(account.person is None)

    def test_register_out_of_session(self):
        self.test_register(reset_client=True)

    def test_password_reset(self, reset_client=False):
        """Resetting the password."""
        # user should be registered with a confirmed email address
        self.test_register()
        self.client.logout()

        response = self.client.get('/+forgot_password', follow=True)
        reset_pwd_expected = "Reset your {0} password".format(
            settings.BRAND_DESCRIPTION)
        self.assertContains(response, reset_pwd_expected)

        response = self.client.post(
            '/+forgot_password', data=dict(email=self.new_email), follow=True)
        self.assertContains(response, 'Forgotten your password?')

        link = self.recover_link()
        response = self.client.get(link)
        token = self._get_token(token_type=TokenType.PASSWORDRECOVERY)
        link = reverse('reset_password',
                       kwargs=dict(authtoken=token,
                                   email_address=self.new_email))
        self.assertRedirects(response, link)

        if reset_client:
            # Try to confirm the new account from out of the original session.
            self.reset_client()

        response = self.client.get(link)
        self.assertContains(response, reset_pwd_expected)

        new_pwd = 'new Passw0rd'
        data = dict(password=new_pwd, passwordconfirm=new_pwd)
        response = self.client.post(link, data=data)
        self.assertRedirects(response, reverse('account-index'))

        # Log in with the new password.
        self.client.logout()
        success = self.client.login(username=self.new_email, password=new_pwd)
        self.assertTrue(success)
        response = self.client.get(reverse('account-index'))
        self.assertContains(response, "New User")

    def test_password_reset_out_of_session(self):
        self.test_password_reset(reset_client=True)

    def test_add_new_email(self):
        """Adding an e-mail address."""
        response = self.login()

        response = self.client.get(reverse('account-edit'))
        link = self.get_attribute_from_response(
            response,
            'a[data-qa-id="_qa_manage_email_addresses_link"]',
            'href')
        response = self.client.get(link)
        self.assertContains(response, 'Your email addresses')
        self.assertNotContains(response, self.new_email)
        self.assertContains(response, 'Add email address')

        data = dict(newemail=self.new_email)
        response = self.client.post(reverse('new_email'),
                                    data=data, follow=True)
        self.assertContains(response, 'Validate your email address')
        msg = ('just emailed %s (from noreply@ubuntu.com) with '
               'instructions on validating your email address.')
        self.assertContains(response, msg % self.new_email)

        link = self.new_email_link()
        response = self.client.get(link)
        token = self._get_token(token_type=TokenType.VALIDATEEMAIL)
        link = reverse('confirm_email',
                       kwargs=dict(authtoken=token,
                                   email_address=self.new_email))
        self.assertRedirects(response, link)

        response = self.client.get(link)
        self.assertContains(response, 'Validate %s?' % self.new_email)
        msg = 'Are you sure you want to confirm and validate this email'
        self.assertContains(response, msg)
        button = self.submit_from_response(response)
        self.assertIn('Yes, I\'m sure', button.text_content())

        # confirm new email
        response = self.client.post(link)

        self.client.logout()
        response = self.login(email=self.new_email)

        self.assertContains(response, "Full name")
        self.assertContains(response, self.new_email)
