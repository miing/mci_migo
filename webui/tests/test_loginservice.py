# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.conf import settings
from django.core import mail

from identityprovider.models.authtoken import AuthToken

from identityprovider.tests.utils import SSOBaseTestCase
from identityprovider.utils import get_current_brand

from unittest import skipUnless


class LoginTest(SSOBaseTestCase):

    def test_loginform_password_did_not_match_error(self):
        r = self.client.post('/+login', {'email': "mark@example.com",
                                         'password': "foo"})
        self.assertFormError(r, 'form', None, "Password didn't match.")

    def test_loginform_wrong_email_error(self):
        r = self.client.post('/+login', {'email': "foo@"})
        self.assertFormError(r, 'form', 'email', "Invalid email.")

    def test_loginform_password_required_error(self):
        r = self.client.post('/+login', {'email': "mark@example.com",
                                         'passwrd': ""})
        self.assertFormError(r, 'form', 'password', "Required field.")


@skipUnless(settings.BRAND == 'ubuntuone',
            "Hybrid login/create account page only applies to u1 brand""")
class HybridLoginNewAccountTest(SSOBaseTestCase):

    def test_create_account_form_required_field(self):
        r = self.client.get('/+login')
        self.assertIn("login_create_account_radio", r.content)

        self.assertIn("login_form", r.content)
        self.assertIn("create_account_form", r.content)


class NewAccountTest(SSOBaseTestCase):

    @skipUnless(settings.BRAND == 'ubuntu',
                "u1 and ubuntu brands use different text""")
    def test_newaccount_existing(self):
        query = {
            'email': 'nobody@debian.org',
        }
        response = self.client.post('/+forgot_password', query)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Forgotten your password?", response.content)
        self.assertIn("nobody@debian.org", response.content)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(
            mail.outbox[0].subject,
            u"%s: Password reset request" % settings.BRAND_DESCRIPTIONS.get(
                get_current_brand()))
        self.assertTrue('nobody@debian.org' in mail.outbox[0].body)
        self.assertTrue('+new_account' in mail.outbox[0].body)

    @skipUnless(settings.BRAND == 'ubuntuone',
                "u1 uses reset rather than forgot in text""")
    def test_newaccount_existing_ubuntuone(self):
        query = {
            'email': 'nobody@debian.org',
        }
        response = self.client.post('/+forgot_password', query)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Reset password", response.content)
        self.assertIn("nobody@debian.org", response.content)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(
            mail.outbox[0].subject,
            u"%s: Password reset request" % settings.BRAND_DESCRIPTIONS.get(
                get_current_brand()))
        self.assertTrue('nobody@debian.org' in mail.outbox[0].body)
        self.assertTrue('+new_account' in mail.outbox[0].body)

    @skipUnless(settings.BRAND == 'ubuntuone',
                "TOS testing only apply to ubuntuone brand""")
    def test_newaccount_no_tos_accept(self):
        r = self.client.post('/+new_account', {
            'email': "mark@example.com",
            'password': "foofoofoo",
            'passwordconfirm': "foofoofoo",
            'displayname': 'bar'
        })

        s = ("Check the box to indicate that "
             "you agree with our terms of use:")

        self.assertFormError(r, 'form', 'accept_tos', s)


class ForgottenPasswordTest(SSOBaseTestCase):

    fixtures = ["test"]

    def test_forgottenpass_nonexisting(self):
        query = {
            'displayname': 'Tester',
            'email': 'test@canonical.com',
            'password': 'Testing123',
            'passwordconfirm': 'Testing123',
            'accept_tos': True,
            'recaptcha_challenge_field': 'ignored',
            'recaptcha_response_field': 'ignored',
        }
        response = self.client.post('/+new_account', query)
        self.assertEqual(response.status_code, 200)
        self.assertIn("test@canonical.com", response.content)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject,
                         u"%s: Warning" % settings.BRAND_DESCRIPTIONS.get(
                             get_current_brand()))
        mail.outbox = []

    @skipUnless(settings.BRAND == 'ubuntu',
                "u1 uses reset rather than forgot in text""")
    def test_forgottenform_success(self):
        query = {
            'email': 'test@canonical.com',
        }
        response = self.client.post('/+forgot_password', query)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Forgotten your password?", response.content)
        self.assertIn("test@canonical.com", response.content)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(
            mail.outbox[0].subject,
            u"%s: Forgotten Password" % settings.BRAND_DESCRIPTIONS.get(
                get_current_brand()))
        mail.outbox = []

        AuthToken.objects.all().delete()

    @skipUnless(settings.BRAND == 'ubuntuone',
                "u1 uses reset rather than forgot in text""")
    def test_resetform_success(self):
        query = {
            'email': 'test@canonical.com',
        }
        response = self.client.post('/+forgot_password', query)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Reset password", response.content)
        self.assertIn("test@canonical.com", response.content)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(
            mail.outbox[0].subject,
            u"%s: Forgotten Password" % settings.BRAND_DESCRIPTIONS.get(
                get_current_brand()))
        mail.outbox = []

        AuthToken.objects.all().delete()
