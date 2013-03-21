# -*- coding: utf-8 -*-

# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from api.v10.forms import WebserviceCreateAccountForm

from identityprovider.tests.utils import (
    SSOBaseTestCase,
    patch_settings,
)


class WebServiceCreateAccountFormTest(SSOBaseTestCase):

    def setUp(self):
        super(WebServiceCreateAccountFormTest, self).setUp()
        p = patch_settings(DISABLE_CAPTCHA_VERIFICATION=True)
        p.start()
        self.addCleanup(p.stop)

    def test_nonascii_password(self):
        data = {'password': 'Curuzú Cuatiá',
                'remote_ip': '127.0.0.1'}
        form = WebserviceCreateAccountForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors['password'][0],
                         'Invalid characters in password')

    def test_default_platform(self):
        form = WebserviceCreateAccountForm()
        self.assertEqual(form.fields['platform'].empty_value, 'desktop')

    def test_default_cleaned_platform(self):
        data = {
            'email': 'some@email.com',
            'password': 'password1A',
            'captcha_id': '1',
            'captcha_solution': '2',
            'remote_ip': '127.0.0.1',
        }
        form = WebserviceCreateAccountForm(data)
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['platform'], 'desktop')

    def test_captcha_checked_for_whitelist(self):
        data = {
            'email': 'canonicaltest@gmail.com',
            'password': 'password1A',
            'captcha_id': '1',
            'captcha_solution': '2',
            'remote_ip': '127.0.0.1',
        }
        pattern = '^canonicaltest(?:\+.+)?@gmail\.com$'
        overrides = dict(
            DISABLE_CAPTCHA_VERIFICATION=False,
            EMAIL_WHITELIST_REGEXP_LIST=[pattern],
        )
        with patch_settings(**overrides):
            form = WebserviceCreateAccountForm(data)
            self.assertTrue(form.is_valid())

    def test_default_cleaned_validate_redirect_to(self):
        data = {
            'email': 'some@email.com',
            'password': 'password1A',
            'captcha_id': '1',
            'captcha_solution': '2',
            'remote_ip': '127.0.0.1',
        }
        form = WebserviceCreateAccountForm(data)
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['validate_redirect_to'], None)
