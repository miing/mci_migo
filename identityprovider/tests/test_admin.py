# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

from django.contrib import admin
from django.contrib.admin.sites import (
    AdminSite,
    AlreadyRegistered,
    NotRegistered,
)
from django.core.urlresolvers import reverse
from mock import patch
from pyquery import PyQuery

from identityprovider.admin import (
    AccountPasswordInline,
    AuthenticationDeviceInline,
    AuthenticationDeviceInlineForm,
    EmailAddressAdmin,
    EmailAddressInline,
    InvalidatedEmailAddress,
    InvalidatedEmailAddressAdmin,
)
from identityprovider.models import (
    Account,
    AccountPassword,
    APIUser,
    AuthenticationDevice,
    EmailAddress,
    LPOpenIdIdentifier,
    OpenIDRPConfig,
    Person,
)
from identityprovider.models.const import EmailStatus
from identityprovider.utils import validate_launchpad_password
from identityprovider.tests.utils import SSOBaseTestCase


class AdminTestCase(SSOBaseTestCase):

    fixtures = ['admin', 'test']

    def setUp(self):
        super(AdminTestCase, self).setUp()
        self.client.login(username="admin", password="admin007")
        self.account = Account.objects.get(pk=1)

    def test_registered_models(self):
        for model in (Account, OpenIDRPConfig, APIUser, EmailAddress):
            self.assertRaises(AlreadyRegistered, admin.site.register, model)

        for model in (AccountPassword, Person, LPOpenIdIdentifier):
            self.assertRaises(NotRegistered, admin.site.unregister, model)

    def test_openidrpconfig_allowed_sreg_checkboxes_postable(self):
        trust_root = 'http://localhost/bla/'
        displayname = 'My Test RP'
        description = 'Bla'
        allowed_sreg = ['fullname', 'email']
        creation_rationale = 13

        data = {'trust_root': trust_root,
                'displayname': displayname,
                'description': description,
                'allowed_sreg': allowed_sreg,
                'creation_rationale': creation_rationale,
                }
        add_view = reverse('admin:identityprovider_openidrpconfig_add')
        response = self.client.get(add_view)
        response = self.client.post(add_view, data)
        self.assertEqual(302, response.status_code)
        # We don't get the ID back, so ensure we only have one entity and
        # assume it's the correct one.  This is racy, but the alternative is
        # another request to the list screen to scrape the ID from there.
        self.assertEqual(OpenIDRPConfig.objects.count(), 1)
        rpconfig = OpenIDRPConfig.objects.get()
        self.assertEqual(rpconfig.trust_root, trust_root)
        self.assertEqual(rpconfig.displayname, displayname)
        self.assertEqual(rpconfig.description, description)
        self.assertEqual(sorted(rpconfig.allowed_sreg.split(',')),
                         sorted(allowed_sreg))
        self.assertEqual(rpconfig.creation_rationale, creation_rationale)

    def test_openidrpconfig_allowed_sreg_checkboxes_getable(self):
        data = {'trust_root': 'http://localhost/bla/',
                'displayname': 'My Test RP',
                'description': 'Bla',
                'allowed_sreg': 'fullname',
                'creation_rationale': '13',
                }
        rpconfig = OpenIDRPConfig.objects.create(**data)
        change_view = reverse(
            'admin:identityprovider_openidrpconfig_change',
            args=(rpconfig.id,))
        response = self.client.get(change_view)
        dom = PyQuery(response.content)
        checked = dom.find('input[checked=checked]')
        self.assertEqual(len(checked), 1)
        self.assertEqual(checked[0].value, 'fullname')

    def test_openidrpconfig_allowed_ax_checkboxes_postable(self):
        trust_root = 'http://localhost/bla/'
        displayname = 'My Test RP'
        description = 'Bla'
        allowed_ax = ['fullname', 'email']
        creation_rationale = 13

        data = {'trust_root': trust_root,
                'displayname': displayname,
                'description': description,
                'allowed_ax': allowed_ax,
                'creation_rationale': creation_rationale,
                }
        add_view = reverse('admin:identityprovider_openidrpconfig_add')
        response = self.client.get(add_view)
        response = self.client.post(add_view, data)
        self.assertEqual(302, response.status_code)
        # We don't get the ID back, so ensure we only have one entity and
        # assume it's the correct one.  This is racy, but the alternative is
        # another request to the list screen to scrape the ID from there.
        self.assertEqual(OpenIDRPConfig.objects.count(), 1)
        rpconfig = OpenIDRPConfig.objects.get()
        self.assertEqual(rpconfig.trust_root, trust_root)
        self.assertEqual(rpconfig.displayname, displayname)
        self.assertEqual(rpconfig.description, description)
        self.assertEqual(sorted(rpconfig.allowed_ax.split(',')),
                         sorted(allowed_ax))
        self.assertEqual(rpconfig.creation_rationale, creation_rationale)

    def test_openidrpconfig_allowed_ax_checkboxes_getable(self):
        data = {'trust_root': 'http://localhost/bla/',
                'displayname': 'My Test RP',
                'description': 'Bla',
                'allowed_ax': 'email',
                'creation_rationale': '13',
                }
        rpconfig = OpenIDRPConfig(**data)
        rpconfig.save()
        change_view = reverse(
            'admin:identityprovider_openidrpconfig_change',
            args=(rpconfig.id,))
        response = self.client.get(change_view)
        dom = PyQuery(response.content)
        checked = dom.find('input[checked=checked]')
        self.assertEqual(len(checked), 1)
        self.assertEqual(checked[0].value, 'email')

    def test_inline_models(self):
        expected_inlines = [AccountPasswordInline, EmailAddressInline,
                            AuthenticationDeviceInline]
        registered_inlines = admin.site._registry[Account].inlines
        self.assertEqual(registered_inlines, expected_inlines)

    def test_account_overview(self):
        changelist_view = reverse('admin:identityprovider_account_changelist')
        r = self.client.get(changelist_view)
        self.assertContains(r, self.account.preferredemail)

    def post_account_change(self, success=True, **kwargs):
        account_id = self.account.id
        email = self.account.preferredemail
        change_view = reverse(
            'admin:identityprovider_account_change', args=(account_id,))
        parameters = {
            'creation_rationale': str(self.account.creation_rationale),
            'status': str(self.account.status),
            'displayname': self.account.displayname,
            'openid_identifier': self.account.openid_identifier,
            'accountpassword-TOTAL_FORMS': '1',
            'accountpassword-INITIAL_FORMS': '1',
            'accountpassword-0-id': str(account_id),
            'accountpassword-0-account': str(account_id),
            'emailaddress_set-TOTAL_FORMS': '1',
            'emailaddress_set-INITIAL_FORMS': '1',
            'emailaddress_set-0-id': str(email.id),
            'emailaddress_set-0-account': str(account_id),
            'emailaddress_set-0-email': email,
            'emailaddress_set-0-status': str(email.status),
            'devices-TOTAL_FORMS': '0',
            'devices-INITIAL_FORMS': '0',
        }
        parameters.update(kwargs)
        r = self.client.post(change_view, parameters)

        if success:
            # Any non-error status code would be fine here, but right now
            # it redirects with a 302.
            self.assertEqual(r.status_code, 302)
        return r

    def test_account_change(self):
        new_email = 'mark2@example.com'
        new_password = 'blah'
        parameters = {
            'emailaddress_set-0-email': new_email,
            'accountpassword-0-password': new_password,
        }
        self.post_account_change(**parameters)

        account = Account.objects.get(id=self.account.id)
        self.assertEqual(account.preferredemail.email, new_email)
        self.assertTrue(validate_launchpad_password(
            new_password, account.accountpassword.password))

    def test_device_change(self):
        device = AuthenticationDevice.objects.create(
            account=self.account,
            key='some key',
            name='Some device',
            counter=124,
            device_type=None,
        )
        parameters = {
            'devices-TOTAL_FORMS': '1',
            'devices-INITIAL_FORMS': '1',
            'devices-0-id': str(device.id),
            'devices-0-key': 'some key',
            'devices-0-name': 'Some device',
            'devices-0-counter': '123',
            'devices-0-device_type': 'paper',
        }
        self.post_account_change(**parameters)

        device = AuthenticationDevice.objects.get(id=device.id)
        self.assertEqual(device.counter, 123)
        self.assertEqual(device.device_type, 'paper')

    def get_device_inlineform(self, device_type):
        device = AuthenticationDevice.objects.create(
            account=self.account,
            key='some key',
            name='Some device',
            counter=124,
            device_type=None,
        )
        post_data = {
            'key': 'other key',
            'name': 'A device',
            'counter': '123',
            'device_type': device_type,
        }
        form = AuthenticationDeviceInlineForm(post_data, instance=device)
        return form

    def test_device_inlineform_invalid_type(self):
        form = self.get_device_inlineform(device_type='foobar')
        device = AuthenticationDevice.objects.all()[0]
        expected_defaults = {
            'id': device.id,
            'key': 'some key',
            'name': 'Some device',
            'counter': 124,
            'device_type': None,
        }
        self.assertEqual(form.initial, expected_defaults)
        self.assertEqual(form.is_valid(), False)

        msg = ('Select a valid choice. foobar is not one of the '
               'available choices.')
        expected_errors = {'device_type': [msg]}
        self.assertEqual(form.errors, expected_errors)

    def test_device_inlineform_valid_type(self):
        form = self.get_device_inlineform(device_type='None')
        self.assertEqual(form.is_valid(), True)

    def test_multiple_preferred_emails(self):
        email = self.account.preferredemail
        parameters = {
            'emailaddress_set-TOTAL_FORMS': '2',
            'emailaddress_set-1-account': str(self.account.id),
            'emailaddress_set-1-email': 'failure@example.com',
            'emailaddress_set-1-status': str(EmailStatus.PREFERRED),
        }
        r = self.post_account_change(success=False, **parameters)

        account = Account.objects.get(pk=1)
        self.assertContains(r, 'Only one email address can be preferred.')
        self.assertEqual(len(account.emailaddress_set.filter(
                         status=EmailStatus.PREFERRED)), 1)
        self.assertEqual(account.preferredemail, email)

    def test_inline_forms(self):
        change_view = reverse('admin:identityprovider_account_change',
                              args=(self.account.id,))
        r = self.client.get(change_view)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, '<input type="password" '
                            'name="accountpassword-0-password"')

    def test_add_api_user(self):
        add_view = reverse('admin:identityprovider_apiuser_add')
        r = self.client.post(add_view, {
            'username': 'api_user',
            'password': 'backend'})
        self.assertEqual(r.status_code, 302)

    def test_login_nexus(self):
        login_url = reverse('nexus:index')
        self.client.logout()

        response = self.client.get(login_url)

        tree = PyQuery(response.content)
        next_url = tree.find('form[name="fopenid"]').find(
            'input[name="next"]')[0].value
        self.assertEqual(next_url, login_url)


class RPAdminTestCase(SSOBaseTestCase):

    fixtures = ["admin"]

    def setUp(self):
        super(RPAdminTestCase, self).setUp()

        OpenIDRPConfig.objects.create(trust_root="test", displayname="test",
                                      description="test")
        self.client.login(username="admin", password="admin007")

    def _get_form(self):
        path = reverse("admin:identityprovider_openidrpconfig_add")
        return self.client.get(path)

    def _get_table(self):
        path = reverse("admin:identityprovider_openidrpconfig_changelist")
        return self.client.get(path)

    def test_form_has_2f_checkbox(self):
        r = self._get_form()
        self.assertContains(
            r, '<input type="checkbox" name="require_two_factor"')

    def test_table_has_2f_column(self):
        r = self._get_table()
        self.assertContains(r, "Require two factor\n</a></th>")

    def test_table_2f_is_editable(self):
        r = self._get_table()
        self.assertContains(
            r, '<input type="checkbox" name="form-0-require_two_factor"')

    def test_table_is_filterable_by_2f(self):
        r = self._get_table()
        self.assertContains(r, "<h3> By require two factor </h3>")


class EmailAddressAdminTestCase(SSOBaseTestCase):
    fixtures = ["test"]
    model = EmailAddress
    modeladmin = EmailAddressAdmin

    def setUp(self):
        super(EmailAddressAdminTestCase, self).setUp()
        self.admin = self.modeladmin(self.model, AdminSite())

    @patch('identityprovider.admin.reverse')
    def test_account_link(self, mock_reverse):
        mock_reverse.return_value = '/foo'
        xss_displayname = "Sample<script>alert('busted');</script>Person & Co."
        email = EmailAddress.objects.get(email='test@canonical.com')
        email.account.displayname = xss_displayname

        expected = ('<a href="/foo">Sample&lt;script&gt;alert('
                    '&#39;busted&#39;);&lt;/script&gt;Person &amp; Co.</a>')
        self.assertEqual(self.admin.account_link(email), expected)


class InvalidatedEmailAddressAdminTestCase(EmailAddressAdminTestCase):

    model = InvalidatedEmailAddress
    modeladmin = InvalidatedEmailAddressAdmin
