from django.test import TestCase
from django.template.loader import render_to_string
from django.core.urlresolvers import reverse
from identityprovider.tests.utils import SSOBaseUnittestTestCase
from mock import patch
from pyquery import PyQuery
from gargoyle.testutils import switches

from u1testutils.django import patch_settings

from identityprovider.models.openidmodels import OpenIDRPConfig


class UbuntuLoginTemplateTestCase(TestCase):
    @patch('webui.views.ui.get_rpconfig_from_request')
    def test_rpconfig_with_logo_url(self, mock_get_rpconfig):
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            logo='http://localhost/img.png')
        mock_get_rpconfig.return_value = rpconfig

        response = self.client.get('/+login')
        self.assertTemplateUsed(response, 'registration/login.html')
        self.assertContains(response, "<div id='rpconfig_logo'>")
        self.assertContains(response, "<img src='http://localhost/img.png'/>")

    @patch('webui.views.ui.get_rpconfig_from_request')
    def test_rpconfig_without_logo_url(self, mock_get_rpconfig):
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            logo='')
        mock_get_rpconfig.return_value = rpconfig

        response = self.client.get('/+login')
        self.assertTemplateUsed(response, 'registration/login.html')
        self.assertNotContains(response, "<div id='rpconfig_logo'>")


class NewAccountTemplateTestCase(SSOBaseUnittestTestCase):

    def test_with_logo_url(self):
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            logo='http://localhost/img.png'
        )
        html = render_to_string(
            'registration/new_account.html',
            {'rpconfig': rpconfig}
        )
        self.assertIn('<div id="rpconfig_logo">', html)
        self.assertIn('<img src="http://localhost/img.png"/>', html)

    def test_without_logo_url(self):
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            logo=''
        )
        html = render_to_string(
            'registration/new_account.html',
            {'rpconfig': rpconfig}
        )
        self.assertNotIn('<div id="rpconfig_logo">', html)

    def test_action_without_token(self):
        html = render_to_string('registration/new_account.html', {})
        dom = PyQuery(html)
        form = dom.find('form[name=newaccountform]')
        self.assertEqual(form.attr['action'], reverse('new_account'))

    def test_action_with_token(self):
        ctx = {'token': 'a' * 16}
        html = render_to_string('registration/new_account.html', ctx)
        dom = PyQuery(html)
        form = dom.find('form[name=newaccountform]')
        self.assertEqual(
            form.attr['action'],
            reverse('new_account', kwargs=ctx)
        )

    @switches(ALLOW_UNVERIFIED=False)
    def test_allow_invalidated_switch_off(self):
        html = render_to_string('registration/new_account.html', {})
        self.assertIn(
            'and we will send you instructions on how to confirm',
            html
        )

    @switches(ALLOW_UNVERIFIED=True)
    def test_allow_invalidated_switch_on(self):
        html = render_to_string('registration/new_account.html', {})
        self.assertNotIn(
            'and we will send you instructions on how to confirm',
            html
        )


class UbuntuBaseTemplateTestCase(TestCase):
    def test_base_template_includes_analytics(self):
        # Analytics code is included if the analytics id is set.
        with patch_settings(GOOGLE_ANALYTICS_ID='foobar'):
            response = self.client.get('/')

        self.assertTemplateUsed(response, 'base.html')
        self.assertContains(
            response, "_gaq.push(['_setAccount', 'foobar']);")

    def test_base_template_not_includes_analytics(self):
        # If the analytics id is not set the analitycs code is not
        # included.
        with patch_settings(GOOGLE_ANALYTICS_ID=None):
            response = self.client.get('/')

        self.assertTemplateUsed(response, 'base.html')
        self.assertNotContains(response, "_gaq.push")
