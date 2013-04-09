# -*- coding: utf-8 -*-

# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.http import HttpRequest
from django_openid_auth.teams import TeamsRequest
from mock import patch
from openid.extensions.ax import (
    AttrInfo,
    FetchRequest,
)
from openid.extensions.sreg import SRegRequest

from identityprovider.models.account import Account
from identityprovider.models.const import EmailStatus
from identityprovider.const import (
    AX_URI_FULL_NAME,
    AX_URI_EMAIL,
)
from identityprovider.forms import (
    AXFetchRequestForm,
    DeviceRenameForm,
    EditAccountForm,
    LoginForm,
    ResetPasswordForm,
    SRegRequestForm,
    TeamsRequestForm,
    TokenForm,
)
from identityprovider.models.openidmodels import OpenIDRPConfig
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import SSOBaseTestCase


class EditAccountFormTestCase(SSOBaseTestCase):

    def setUp(self):
        super(EditAccountFormTestCase, self).setUp()
        self.account = self.factory.make_account(
            openid_identifier='name12_oid', displayname='Sample Person')
        # add an extra unverified email
        self.unverified_email = self.factory.make_email_for_account(
            account=self.account, status=EmailStatus.NEW)

        assert self.account.verified_emails().exists()
        assert self.account.unverified_emails().exists()

    def get_form(self, **kwargs):
        return EditAccountForm(instance=self.account, **kwargs)

    def assert_form_is_valid(self, form):
        msg = 'Form %r should be valid, but got errors:\n%s'
        assert form.is_valid(), msg % (form, form.errors)

    def test_initial_displayname(self):
        form = self.get_form()
        self.assertEqual(form.initial.get('displayname', ''), 'Sample Person')

    def test_nonascii_password(self):
        data = {'password': 'changüí'}
        form = self.get_form(data=data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors['password'][0],
                         'Invalid characters in password')

    def test_no_preferredemail(self):
        # replace preferredemail property
        with patch.object(Account, 'preferredemail', None):
            form = self.get_form()

        self.assertEqual(form.initial.get('displayname', ''), "Sample Person")

    def test_account_without_validated_emails_no_field(self):
        self.account.emailaddress_set.update(status=EmailStatus.NEW)
        form = self.get_form()
        self.assertNotIn('preferred_email', form.fields)

    def test_account_with_validated_emails_editable_field(self):
        form = self.get_form()
        self.assertIn('preferred_email', form.fields)
        choices = form.fields['preferred_email'].queryset.all()
        valid_choices = self.account.verified_emails()
        self.assertEqual(choices.count(), valid_choices.count())
        for email in choices:
            self.assertIn(email, valid_choices)

    def test_account_without_validated_emails_post_preferred_email(self):
        self.account.emailaddress_set.update(status=EmailStatus.NEW)
        original_value = self.account.preferredemail
        invalid_email = self.account.unverified_emails()[0]
        form = self.get_form(data={'displayname': self.account.displayname,
                                   'preferred_email': invalid_email.id})
        self.assert_form_is_valid(form)
        form.save()
        account = Account.objects.get(id=self.account.id)
        self.assertEqual(account.preferredemail, original_value)

    def test_account_with_validated_email_changing_to_unvalidate(self):
        invalid_email = self.account.unverified_emails()[0]
        form = self.get_form(data={'displayname': self.account.displayname,
                                   'preferred_email': invalid_email.id})
        self.assertFalse(form.is_valid())

    def test_displayname_validation(self):
        form = self.get_form(data={'displayname': ' '})
        self.assertFalse(form.is_valid())
        self.assertTrue(form.errors['displayname'] == [u'Required field'])
        form = self.get_form(data={'displayname': 'Sample Person'})
        self.assertFalse(form.is_valid())
        self.assertFalse('displayname' in form.errors)

    def test_newpassword_mismatch_validation(self):
        form = self.get_form(data={'password': 'tooweak',
                                   'passwordconfirm': 'other'})
        self.assertFalse(form.is_valid())
        self.assertEqual(1, len(form.errors['password']))
        self.assertFalse('passwordconfirm' in form.errors)
        self.assertEqual(0, len(form.non_field_errors()))

    def test_newpassword_validation(self):
        form = self.get_form(data={'password': 'tooweak',
                                   'passwordconfirm': 'tooweak'})
        self.assertFalse(form.is_valid())
        self.assertEqual(1, len(form.errors['password']))
        self.assertFalse('passwordconfirm' in form.errors)
        self.assertEqual(0, len(form.non_field_errors()))

    def test_device_preferences(self):
        form = self.get_form()
        self.assertNotIn('twofactor_required', form.fields)
        self.assertNotIn('warn_about_backup_device', form.fields)

    def test_device_preferences_edited(self):
        self.account.twofactor_required = True
        self.account.save()

        assert self.account.twofactor_required
        assert self.account.warn_about_backup_device

        data = dict(
            preferred_email=self.account.preferredemail.id,
            displayname='Zaraza New',
        )
        form = self.get_form(data=data)

        self.assert_form_is_valid(form)
        form.save()
        account = Account.objects.get(id=self.account.id)  # reload!
        self.assertTrue(account.twofactor_required)
        self.assertTrue(account.warn_about_backup_device)


class EditAccountFormDevicePrefsEnabledTestCase(EditAccountFormTestCase):

    def get_form(self, **kwargs):
        return EditAccountForm(
            instance=self.account, enable_device_prefs=True, **kwargs)

    def test_device_preferences(self):
        form = self.get_form()
        self.assertIn('twofactor_required', form.fields)
        self.assertIn('warn_about_backup_device', form.fields)

    def test_twofactor_required_initial_false(self):
        assert not self.account.twofactor_required
        form = self.get_form()
        self.assertEqual(form.initial.get('twofactor_required'), False)

    def test_twofactor_required_initial_true(self):
        self.account.twofactor_required = True
        self.account.save()
        form = self.get_form()
        self.assertEqual(form.initial.get('twofactor_required'), True)

    def test_twofactor_required_changed_in_form(self):
        new_value = not self.account.twofactor_required
        data = dict(
            twofactor_required=new_value,
            preferred_email=self.account.preferredemail.id,
            displayname=self.account.displayname,
        )
        form = self.get_form(data=data)

        # reload account without saving the form
        account = Account.objects.get(id=self.account.id)
        self.assertEqual(account.twofactor_required, not new_value)

        # reload account after saving the form
        self.assert_form_is_valid(form)
        form.save()
        account = Account.objects.get(id=self.account.id)
        self.assertEqual(account.twofactor_required, new_value)

    def test_warn_about_backup_device_initial_true(self):
        assert self.account.warn_about_backup_device
        form = self.get_form()
        self.assertEqual(form.initial.get('warn_about_backup_device'), True)

    def test_warn_about_backup_device_initial_false(self):
        self.account.warn_about_backup_device = False
        form = self.get_form()
        self.assertEqual(form.initial.get('warn_about_backup_device'), False)

    def test_warn_about_backup_device_changed_in_form(self):
        new_value = not self.account.warn_about_backup_device
        data = dict(
            warn_about_backup_device=new_value,
            preferred_email=self.account.preferredemail.id,
            displayname=self.account.displayname,
        )
        form = self.get_form(data=data)

        # reload account without saving the form
        account = Account.objects.get(id=self.account.id)
        self.assertEqual(account.warn_about_backup_device, not new_value)

        # reload account after saving the form
        self.assert_form_is_valid(form)
        form.save()
        account = Account.objects.get(id=self.account.id)
        self.assertEqual(account.warn_about_backup_device, new_value)

    def test_device_preferences_edited(self):
        self.account.twofactor_required = True
        self.account.save()

        assert self.account.twofactor_required
        assert self.account.warn_about_backup_device

        data = dict(
            preferred_email=self.account.preferredemail.id,
            displayname='Zaraza New',
        )
        form = self.get_form(data=data)

        self.assert_form_is_valid(form)
        form.save()
        account = Account.objects.get(id=self.account.id)  # reload!
        self.assertFalse(account.twofactor_required)
        self.assertFalse(account.warn_about_backup_device)


class ResetPasswordFormTest(SSOBaseTestCase):

    def test_nonascii_password(self):
        data = {'password': 'Ñandú'}
        form = ResetPasswordForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors['password'][0],
                         'Invalid characters in password')


class SRegRequestFormTest(SSOBaseTestCase):

    def _get_request_with_post_args(self, args={}):
        request = HttpRequest()
        request.user = self.test_user
        request.POST = args
        request.META = {'REQUEST_METHOD': 'POST'}
        return request

    def setUp(self):
        super(SRegRequestFormTest, self).setUp()
        self.test_user = Account.objects.create_account(
            'My name', 'me@test.com', DEFAULT_USER_PASSWORD)
        self.rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://localhost/', description="Some description")

    def test_no_approved_fields_without_post_request(self):
        """The server should not generate a list of approved fields when the
        request is not a POST request.
        """
        request = self._get_request_with_post_args()
        request.META['REQUEST_METHOD'] = 'GET'
        form = SRegRequestForm(
            request,
            SRegRequest(required=['fullname', 'email']),
            self.rpconfig)
        self.assertEqual(len(form.data_approved_for_request), 0)

    def test_required_fields_for_trusted_site(self):
        """The server should always return values for required fields to
        trusted sites, regardless of the state of the checkbox in the UI.
        Optional fields should not be returned if the user has unchecked them.
        """
        self.rpconfig.allowed_sreg = 'fullname,email'
        form = SRegRequestForm(
            self._get_request_with_post_args(),
            SRegRequest(required=['fullname'], optional=['email']),
            self.rpconfig)
        self.assertIn('fullname', form.data_approved_for_request)
        self.assertNotIn('email', form.data_approved_for_request)

    def test_optional_fields_for_trusted_site(self):
        """The server should return values for optional fields to trusted
        sites only when the user checks the checkbox in the UI.
        """
        self.rpconfig.allowed_sreg = 'fullname,email'
        post_args = {'email': 'email'}
        form = SRegRequestForm(
            self._get_request_with_post_args(post_args),
            SRegRequest(optional=['fullname', 'email']),
            self.rpconfig)
        self.assertFalse('fullname' in form.data_approved_for_request)
        self.assertTrue('email' in form.data_approved_for_request)

    def test_required_fields_for_untrusted_site(self):
        """The server should return values for required fields to untrusted
        sites only when the user checks the checkbox in the UI.
        """
        post_args = {'email': 'email'}
        form = SRegRequestForm(
            self._get_request_with_post_args(post_args),
            SRegRequest(required=['fullname', 'email']),
            None)
        self.assertFalse('fullname' in form.data_approved_for_request)
        self.assertTrue('email' in form.data_approved_for_request)

    def test_optional_fields_for_untrusted_site(self):
        """The server should return values for optional fields to untrusted
        sites only when the user checks the checkbox in the UI.
        """
        post_args = {'fullname': 'fullname'}
        form = SRegRequestForm(
            self._get_request_with_post_args(post_args),
            SRegRequest(optional=['fullname', 'email']),
            None)
        self.assertTrue('fullname' in form.data_approved_for_request)
        self.assertFalse('email' in form.data_approved_for_request)

    def test_checkbox_status_for_trusted_site(self):
        """Checkboxes are always checked if the site is trusted
        """
        form = SRegRequestForm(
            self._get_request_with_post_args(),
            SRegRequest(required=['fullname'], optional=['email']),
            self.rpconfig)
        self.assertTrue(form.check_test('fullname'))
        self.assertTrue(form.check_test('email'))

    def test_checkbox_status_for_trusted_site_with_approved_data(self):
        """If the user has previously approved sending data to a trusted site
        the same checkbox settings should be returned on the next request
        unless those conflict with the required fields.
        """
        approved_data = {
            'requested': ['fullname', 'email'],
            'approved': ['email']}
        form1 = SRegRequestForm(
            self._get_request_with_post_args(),
            SRegRequest(required=['fullname'], optional=['email']),
            self.rpconfig, approved_data=approved_data)
        self.assertTrue(form1.check_test('fullname'))
        self.assertTrue(form1.check_test('email'))

        approved_data['approved'] = []
        form2 = SRegRequestForm(
            self._get_request_with_post_args(),
            SRegRequest(required=['fullname'], optional=['email']),
            self.rpconfig, approved_data=approved_data)
        self.assertFalse(form2.check_test('email'))

    def test_checkbox_status_for_untrusted_site(self):
        """Checkboxes are only checked on untrusted site requests if the field
        is required
        """
        form = SRegRequestForm(
            self._get_request_with_post_args(),
            SRegRequest(required=['fullname'], optional=['email']),
            None)
        self.assertTrue(form.check_test('fullname'))
        self.assertFalse(form.check_test('email'))

    def test_checkbox_status_for_untrusted_site_with_approved_data(self):
        """If the user has previously approved sending data to an untrusted
        site the same checkbox settings should be returned on the next request.
        """
        approved_data = {
            'requested': ['fullname', 'email'],
            'approved': ['email']}
        form = SRegRequestForm(
            self._get_request_with_post_args(),
            SRegRequest(required=['fullname'], optional=['email']),
            None, approved_data=approved_data)
        self.assertFalse(form.check_test('fullname'))
        self.assertTrue(form.check_test('email'))


class AXFetchRequestFormTestCase(SSOBaseTestCase):
    """AX Fetch Request form tests.

    This is all functionally very similar to Simple Registration, except that
    the extensibility of AX adds an extra layer of complexity.
    """

    def _get_request_with_post_args(self, args={}):
        request = HttpRequest()
        request.user = self.test_user
        request.POST = args
        request.META = {'REQUEST_METHOD': 'POST'}
        return request

    def setUp(self):
        super(AXFetchRequestFormTestCase, self).setUp()
        self.test_user = Account.objects.create_account(
            'My name', 'me@test.com', DEFAULT_USER_PASSWORD)
        self.rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://localhost/', description="Some description")

    def test_no_approved_fields_without_post_request(self):
        """The server should not generate a list of approved fields when the
        request is not a POST request.
        """
        request = self._get_request_with_post_args()
        request.META['REQUEST_METHOD'] = 'GET'
        fetch_request = FetchRequest()
        for (attr, alias) in [
                (AX_URI_FULL_NAME, 'fullname'),
                (AX_URI_EMAIL, 'email')]:
            fetch_request.add(AttrInfo(attr, alias=alias, required=True))
        form = AXFetchRequestForm(request, fetch_request, self.rpconfig)
        self.assertEqual(len(form.data_approved_for_request), 0)

    def test_required_fields_for_trusted_site(self):
        """The server should always return values for required fields to
        trusted sites, regardless of the state of the checkbox in the UI.
        Optional fields should not be returned if the user has unchecked them.
        """
        self.rpconfig.allowed_ax = 'fullname,email'
        fetch_request = FetchRequest()
        fetch_request.add(
            AttrInfo(AX_URI_FULL_NAME, alias='fullname', required=True))
        fetch_request.add(
            AttrInfo(AX_URI_EMAIL, alias='email', required=False))
        form = AXFetchRequestForm(self._get_request_with_post_args(),
                                  fetch_request, self.rpconfig)
        self.assertTrue('fullname' in form.data_approved_for_request)
        self.assertFalse('email' in form.data_approved_for_request)

    def test_optional_fields_for_trusted_site(self):
        """The server should return values for optional fields to trusted
        sites only when the user checks the checkbox in the UI.
        """
        self.rpconfig.allowed_ax = 'fullname,email'
        post_args = {'email': 'email'}
        fetch_request = FetchRequest()
        for (attr, alias) in [
                (AX_URI_FULL_NAME, 'fullname'),
                (AX_URI_EMAIL, 'email')]:
            fetch_request.add(AttrInfo(attr, alias=alias, required=False))
        form = AXFetchRequestForm(self._get_request_with_post_args(post_args),
                                  fetch_request, self.rpconfig)
        self.assertFalse('fullname' in form.data_approved_for_request)
        self.assertTrue('email' in form.data_approved_for_request)

    def test_required_fields_for_untrusted_site(self):
        """The server should return values for required fields to untrusted
        sites only when the user checks the checkbox in the UI.
        """
        post_args = {'email': 'email'}
        fetch_request = FetchRequest()
        for (attr, alias) in [
                (AX_URI_FULL_NAME, 'fullname'),
                (AX_URI_EMAIL, 'email')]:
            fetch_request.add(AttrInfo(attr, alias=alias, required=True))
        form = AXFetchRequestForm(self._get_request_with_post_args(post_args),
                                  fetch_request, None)
        self.assertFalse('fullname' in form.data_approved_for_request)
        self.assertTrue('email' in form.data_approved_for_request)

    def test_optional_fields_for_untrusted_site(self):
        """The server should return values for optional fields to untrusted
        sites only when the user checks the checkbox in the UI.
        """
        post_args = {'fullname': 'fullname'}
        fetch_request = FetchRequest()
        for (attr, alias) in [
                (AX_URI_FULL_NAME, 'fullname'),
                (AX_URI_EMAIL, 'email')]:
            fetch_request.add(AttrInfo(attr, alias=alias, required=False))
        form = AXFetchRequestForm(self._get_request_with_post_args(post_args),
                                  fetch_request, None)
        self.assertTrue('fullname' in form.data_approved_for_request)
        self.assertFalse('email' in form.data_approved_for_request)

    def test_checkbox_status_for_trusted_site(self):
        """Checkboxes are always checked if the site is trusted"""
        fetch_request = FetchRequest()
        fetch_request.add(
            AttrInfo(AX_URI_FULL_NAME, alias='fullname', required=True))
        fetch_request.add(
            AttrInfo(AX_URI_EMAIL, alias='email', required=False))
        form = AXFetchRequestForm(self._get_request_with_post_args(),
                                  fetch_request, self.rpconfig)
        # True because fullname required
        self.assertTrue(form.check_test('fullname'))
        # True because trusted site and no previous disapproval
        self.assertTrue(form.check_test('email'))
        # Throw in an unrequested field for good measure
        self.assertFalse(form.check_test('language'))

    def test_checkbox_status_for_trusted_site_with_approved_data(self):
        """If the user has previously approved sending data to a trusted site
        the same checkbox settings should be returned on the next request
        unless those conflict with the required fields.
        """
        approved_data = {
            'requested': ['fullname', 'email'],
            'approved': ['email', 'language']}
        fetch_request = FetchRequest()
        fetch_request.add(
            AttrInfo(AX_URI_FULL_NAME, alias='fullname', required=True))
        fetch_request.add(
            AttrInfo(AX_URI_EMAIL, alias='email', required=False))
        form1 = AXFetchRequestForm(self._get_request_with_post_args(),
                                   fetch_request, self.rpconfig,
                                   approved_data=approved_data)
        # True because fullname required
        self.assertTrue(form1.check_test('fullname'))
        # True because email previously approved
        self.assertTrue(form1.check_test('email'))
        # Throw in an unrequested, previously-approved field for good measure
        self.assertFalse(form1.check_test('language'))

        approved_data['approved'] = []
        form2 = AXFetchRequestForm(self._get_request_with_post_args(),
                                   fetch_request, self.rpconfig,
                                   approved_data=approved_data)
        # True because fullname required
        self.assertTrue(form1.check_test('fullname'))
        # False because email previously disapproved
        self.assertFalse(form2.check_test('email'))
        # Throw in an unrequested field for good measure
        self.assertFalse(form2.check_test('language'))

    def test_checkbox_status_for_untrusted_site(self):
        """Checkboxes are only checked on untrusted site requests if the field
        is required
        """
        fetch_request = FetchRequest()
        fetch_request.add(
            AttrInfo(AX_URI_FULL_NAME, alias='fullname', required=True))
        fetch_request.add(
            AttrInfo(AX_URI_EMAIL, alias='email', required=False))
        form = AXFetchRequestForm(self._get_request_with_post_args(),
                                  fetch_request, None)
        # True because fullname required
        self.assertTrue(form.check_test('fullname'))
        # False because untrusted site and no previous approval
        self.assertFalse(form.check_test('email'))
        # Throw in an unrequested field for good measure
        self.assertFalse(form.check_test('language'))

    def test_checkbox_status_for_untrusted_site_with_approved_data(self):
        """If the user has previously approved sending data to an untrusted
        site the same checkbox settings should be returned on the next request.
        """
        approved_data = {
            'requested': ['fullname', 'email'],
            'approved': ['email', 'language']}
        fetch_request = FetchRequest()
        fetch_request.add(
            AttrInfo(AX_URI_FULL_NAME, alias='fullname', required=True))
        fetch_request.add(
            AttrInfo(AX_URI_EMAIL, alias='email', required=False))
        form = AXFetchRequestForm(self._get_request_with_post_args(),
                                  fetch_request, None,
                                  approved_data=approved_data)
        # False because untrusted site and previously disapproved
        self.assertFalse(form.check_test('fullname'))
        # True because previously approved
        self.assertTrue(form.check_test('email'))
        # Throw in an unrequested, previously-approved field for good measure
        self.assertFalse(form.check_test('language'))


class TeamsRequestFormTestCase(SSOBaseTestCase):

    def _get_request_with_post_args(self, args={}):
        request = HttpRequest()
        request.user = self.account
        request.POST = args
        request.META = {'REQUEST_METHOD': 'POST'}
        return request

    def setUp(self):
        super(TeamsRequestFormTestCase, self).setUp()
        self.account = self.factory.make_account(teams=['ubuntu-team'])
        self.rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://localhost/', description="Some description",
            can_query_any_team=True)

    def test_selected_teams_for_trusted_sites(self):
        """If a user checks a requested team in the form for a trusted
        consumer, it should be in the list of teams approved by the user.
        """
        post_args = {'ubuntu-team': 'ubuntu-team'}
        form = TeamsRequestForm(
            self._get_request_with_post_args(post_args),
            TeamsRequest(query_membership=['ubuntu-team']),
            self.rpconfig)
        self.assertTrue('ubuntu-team' in form.teams_approved_by_user)

    def test_unselected_teams_for_trusted_sites(self):
        """If a user unchecks a requested team in the form for a trusted
        consumer, it should not be in the list of teams approved by the user.
        """
        form = TeamsRequestForm(
            self._get_request_with_post_args(),
            TeamsRequest(query_membership=['ubuntu-team']),
            self.rpconfig)
        self.assertFalse('ubuntu-team' in form.teams_approved_by_user)

    def test_selected_teams_for_untrusted_sites(self):
        """If a user checks a requested team in the form for an untrusted
        consumer, it should be in the list of teams approved by the user.
        """
        post_args = {'ubuntu-team': 'ubuntu-team'}
        form = TeamsRequestForm(
            self._get_request_with_post_args(post_args),
            TeamsRequest(query_membership=['ubuntu-team']),
            None)
        self.assertTrue('ubuntu-team' in form.teams_approved_by_user)

    def test_unselected_teams_for_untrusted_sites(self):
        """If a user unchecks a requested team in the form for an untrusted
        consumer, it should not be in the list of teams approved by the user.
        """
        form = TeamsRequestForm(
            self._get_request_with_post_args(),
            TeamsRequest(query_membership=['ubuntu-team']),
            None)
        self.assertFalse('ubuntu-team' in form.teams_approved_by_user)

    def test_checkbox_status_for_trusted_site(self):
        """Checkboxes should always be checked by default for trusted sites.
        """
        form = TeamsRequestForm(
            self._get_request_with_post_args(),
            TeamsRequest(query_membership=['ubuntu-team']),
            self.rpconfig)
        self.assertTrue(form.check_test('ubuntu-team'))

    def test_checkbox_status_for_trusted_site_with_approved_data(self):
        """Checkboxes should respect user preferences on trusted sites where
        available.
        """
        approved_data = {
            'requested': ['ubuntu-team', 'myteam'],
            'approved': ['myteam']}
        form = TeamsRequestForm(
            self._get_request_with_post_args(),
            TeamsRequest(query_membership=['ubuntu-team', 'myteam']),
            self.rpconfig, approved_data=approved_data)
        self.assertFalse(form.check_test('ubuntu-team'))
        self.assertTrue(form.check_test('myteam'))

    def test_checkbox_status_for_untrusted_site(self):
        """Checkboxes should always be checked by default for trusted sites.
        """
        form = TeamsRequestForm(
            self._get_request_with_post_args(),
            TeamsRequest(query_membership=['ubuntu-team']),
            None)
        self.assertFalse(form.check_test('ubuntu-team'))

    def test_checkbox_status_for_untrusted_site_with_approved_data(self):
        """Checkboxes should respect user preferences on untrusted sited where
        available.
        """
        approved_data = {
            'requested': ['ubuntu-team'],
            'approved': ['ubuntu-team']}
        form1 = TeamsRequestForm(
            self._get_request_with_post_args(),
            TeamsRequest(query_membership=['ubuntu-team', 'myteam']),
            None, approved_data=approved_data)
        self.assertTrue(form1.check_test('ubuntu-team'))

        approved_data['approved'] = []
        form2 = TeamsRequestForm(
            self._get_request_with_post_args(),
            TeamsRequest(query_membership=['ubuntu-team', 'myteam']),
            None, approved_data=approved_data)
        self.assertFalse(form2.check_test('ubuntu-team'))


class TokenForrmTest(SSOBaseTestCase):

    def test_confirmation_code_error(self):
        data = {'confirmation_code': 'BOGUS', 'email': 'fake@example.com'}
        form = TokenForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form.non_field_errors(), [])
        expected = {'confirmation_code': [u'Unknown confirmation code.']}
        self.assertEqual(form.errors, expected)


class LoginFormTestCase(SSOBaseTestCase):
    def test_clean_email_mixed_case(self):
        self.factory.make_account(email='Test.User@test.com')
        data = {'email': 'Test.User@test.com',
                'password': DEFAULT_USER_PASSWORD}
        form = LoginForm(data=data)
        self.assertTrue(form.is_valid())

        data = {'email': 'test.user@test.com',
                'password': DEFAULT_USER_PASSWORD}
        form = LoginForm(data=data)
        self.assertTrue(form.is_valid())


class DeviceRenameFormTestCase(SSOBaseTestCase):
    def test_clean_name_empty(self):
        account = self.factory.make_account()
        self.factory.make_device(account, name='foo')

        data = {'name': ' '}
        form = DeviceRenameForm(data=data)

        self.assertFalse(form.is_valid())
        expected = ['The name must contain at least one non-whitespace '
                    'character.']
        self.assertEqual(form.errors['name'], expected)

    def test_clean_name_nonempty(self):
        account = self.factory.make_account()
        self.factory.make_device(account, name='foo')

        data = {'name': ' bar '}
        form = DeviceRenameForm(data=data)

        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['name'], 'bar')
