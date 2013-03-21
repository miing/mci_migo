# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.conf import settings
from django.core import mail

from identityprovider.models.authtoken import AuthToken

from identityprovider.tests.utils import SSOBaseTestCase


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


class NewAccountTest(SSOBaseTestCase):

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
            u"%s: Password reset request" % settings.BRAND_DESCRIPTION)
        self.assertTrue('nobody@debian.org' in mail.outbox[0].body)
        self.assertTrue('+new_account' in mail.outbox[0].body)


class ForgottenPasswordTest(SSOBaseTestCase):

    fixtures = ["test"]

    def test_forgottenpass_nonexisting(self):
        query = {
            'displayname': 'Tester',
            'email': 'test@canonical.com',
            'password': 'Testing123',
            'passwordconfirm': 'Testing123'
        }
        response = self.client.post('/+new_account', query)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Account creation mail sent", response.content)
        self.assertIn("test@canonical.com", response.content)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject,
                         u"%s: Warning" % settings.BRAND_DESCRIPTION)
        mail.outbox = []

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
            u"%s: Forgotten Password" % settings.BRAND_DESCRIPTION)
        mail.outbox = []

        AuthToken.objects.all().delete()
