from django.test import TestCase
from django.conf import settings
from django.template.loader import render_to_string
from django.core.urlresolvers import reverse
from identityprovider.tests.utils import SSOBaseUnittestTestCase
from mock import patch
from pyquery import PyQuery
from gargoyle.testutils import switches

from unittest import skipUnless

from u1testutils.django import patch_settings

from identityprovider.models.openidmodels import OpenIDRPConfig
from identityprovider.tests.utils import patch_brand_settings


class UbuntuLoginTemplateTestCase(TestCase):
    @patch('webui.views.ui.get_rpconfig_from_request')
    def test_rpconfig_with_logo_url(self, mock_get_rpconfig):
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            logo='http://localhost/img.png')
        mock_get_rpconfig.return_value = rpconfig

        with patch_brand_settings(BRAND='ubuntu'):
            response = self.client.get('/+login')

        self.assertTemplateUsed(response, 'registration/login.html')
        self.assertContains(response, 'id="rpconfig_logo"')
        self.assertContains(response, 'src="http://localhost/img.png"')

    @patch('webui.views.ui.get_rpconfig_from_request')
    def test_rpconfig_without_logo_url(self, mock_get_rpconfig):
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            logo='')
        mock_get_rpconfig.return_value = rpconfig

        with patch_brand_settings(BRAND='ubuntu'):
            response = self.client.get('/+login')

        self.assertTemplateUsed(response, 'registration/login.html')
        self.assertNotContains(response, 'id="rpconfig_logo"')

    def render_u1_login_with_rpconfig(self, rpconfig):
        with patch_brand_settings(BRAND='ubuntuone'):
            return render_to_string(
                'registration/login.html',
                dict(rpconfig=rpconfig, brand_description="Ubuntu One"))

    def get_title_style_and_text(self, dom):
        titles = dom.find('p[class=title]')
        self.assertEqual(1, titles.length)
        text = " ".join(titles[0].text_content().split())
        style = dom.find('style[data-qa-id=_test_login_rp]')
        if len(style) == 1:
            style = " ".join(style.text().split())
        else:
            style = None

        return style, text

    def test_u1_login_rp_details(self):
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            displayname='Landscape',
            logo='http://localhost/img.png')

        html = self.render_u1_login_with_rpconfig(rpconfig)

        style, text = self.get_title_style_and_text(PyQuery(html))
        self.assertIn("url('http://localhost/img.png')", style)
        self.assertIn(u"Landscape log in with Ubuntu One", text)

    def test_u1_login_rp_no_logo(self):
        """The rp displayname is still included."""
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            displayname='Landscape')

        html = self.render_u1_login_with_rpconfig(rpconfig)

        style, text = self.get_title_style_and_text(PyQuery(html))
        self.assertIsNone(style)
        self.assertIn(u"Landscape log in with Ubuntu One", text)

    def test_u1_login_rp_no_displayname(self):
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            displayname='Landscape',
            logo='http://localhost/img.png')

        html = self.render_u1_login_with_rpconfig(rpconfig)

        style, text = self.get_title_style_and_text(PyQuery(html))
        self.assertIn("url('http://localhost/img.png')", style)
        self.assertIn(u"log in with Ubuntu One", text)


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
        self.assertIn('id="rpconfig_logo"', html)
        self.assertIn('src="http://localhost/img.png"', html)

    def test_without_logo_url(self):
        rpconfig = OpenIDRPConfig(
            trust_root='http://localhost/',
            logo=''
        )
        html = render_to_string(
            'registration/new_account.html',
            {'rpconfig': rpconfig}
        )
        self.assertNotIn('id="rpconfig_logo"', html)

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

    @skipUnless(settings.BRAND == 'ubuntu',
                "Text does not exist in other brands.""")
    @switches(ALLOW_UNVERIFIED=False)
    def test_allow_invalidated_switch_off(self):
        html = render_to_string('registration/new_account.html', {})
        self.assertIn(
            'and we will send you instructions on how to confirm',
            html
        )

    @skipUnless(settings.BRAND == 'ubuntu',
                "Text does not exist in other brands.""")
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
