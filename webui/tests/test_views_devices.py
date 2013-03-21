# Copyright 2012 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from base64 import b16encode

from django.conf import settings
from django.core.urlresolvers import reverse
from django.test import TransactionTestCase
from django.test.client import RequestFactory
from gargoyle.testutils import switches
from pyquery import PyQuery

import mock

from identityprovider.models import Account, AuthenticationDevice
from identityprovider.models.const import AccountStatus
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.factory import SSOObjectFactory
from identityprovider.tests.utils import (
    MISSING_BACKUP_DEVICE,
    SSOBaseTestCase,
    assert_exausted_warning,
    patch_settings,
    test_concurrently,
)

from webui.views.devices import generate_key
from webui.views.ui import TwoFactorView


class DeviceViewsTestCaseBase(SSOBaseTestCase):

    def setUp(self):
        super(DeviceViewsTestCaseBase, self).setUp()
        self.account = account = self.factory.make_account()
        self.device = self.factory.make_device(account, name='foo')

        self.client.login(username=account.preferredemail.email,
                          password=DEFAULT_USER_PASSWORD)

        self.patch_is_upgraded = mock.patch(
            'identityprovider.models.twofactor.is_upgraded')
        self.patch_is_fresh = mock.patch(
            'identityprovider.models.twofactor.is_fresh')
        self.mock_is_upgraded = self.patch_is_upgraded.start()
        self.mock_is_upgraded.return_value = True
        self.mock_is_fresh = self.patch_is_fresh.start()
        self.mock_is_fresh.return_value = True
        self.addCleanup(self.patch_is_upgraded.stop)
        self.addCleanup(self.patch_is_fresh.stop)

        self.switch_twofactor = switches(TWOFACTOR=True)
        self.switch_twofactor.patch()
        self.addCleanup(self.switch_twofactor.unpatch)


class DeviceViewsTestCase(DeviceViewsTestCaseBase):

    def assert_result_length(self, n):
        with mock.patch('webui.views.devices.rand_bytes') as rand:
            rand.return_value = 'a' * n
            s = generate_key(n)
            self.assertEqual(len(s), len(b16encode('a' * n)))

    def test_generate_key(self):
        self.assert_result_length(1)
        self.assert_result_length(10)
        self.assert_result_length(20)


class TwoFactorEnabledMixin(object):
    def test_twofactor_disabled(self):
        name = 'webui.decorators.twofactor.is_twofactor_enabled'
        with mock.patch(name) as mock_enabled:
            mock_enabled.return_value = False
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 404)


class DeviceListViewTestCase(DeviceViewsTestCase, TwoFactorEnabledMixin):
    url = reverse('device-list')

    def test_list_sorted(self):
        # create second device
        self.factory.make_device(self.account, name='bar')

        response = self.client.get(self.url)
        content = response.content
        idx_device = content.find('foo')
        idx_device2 = content.find('bar')
        self.assertNotEqual(idx_device, -1)
        self.assertNotEqual(idx_device2, -1)
        self.assertTrue(idx_device < idx_device2)

    def assert_backup_device_warning(self, show_warning):
        response = self.client.get(self.url)
        backup_warning = MISSING_BACKUP_DEVICE.format(
            add_device_link=reverse('device-addition'))

        if show_warning:
            self.assertContains(response, backup_warning)
        else:
            self.assertNotContains(response, backup_warning)

    def test_backup_device_warning_no_devices(self):
        self.account.devices.all().delete()
        assert self.account.warn_about_backup_device
        assert self.account.devices.count() == 0
        self.assert_backup_device_warning(show_warning=False)

    def test_backup_device_warning_one_device(self):
        assert self.account.warn_about_backup_device
        assert self.account.devices.count() == 1
        self.assert_backup_device_warning(show_warning=True)

    def test_backup_device_warning_one_device_no_warning(self):
        self.account.warn_about_backup_device = False
        self.account.save()

        assert not self.account.warn_about_backup_device
        assert self.account.devices.count() == 1
        self.assert_backup_device_warning(show_warning=False)

    def test_backup_device_warning_two_devices(self):
        self.factory.make_device(account=self.account)

        assert self.account.warn_about_backup_device
        assert self.account.devices.count() == 2
        self.assert_backup_device_warning(show_warning=False)

    def test_codes_exhausted_warning_not_exhausted(self):
        self.device.device_type = 'paper'
        self.device.save()
        response = self.client.get(self.url)
        with self.assertRaises(AssertionError):
            assert_exausted_warning(self, [self.device], response)

    def test_codes_exhausted_warning_exhausted(self):
        self.device.device_type = 'paper'
        counter = (settings.TWOFACTOR_PAPER_CODES -
                   settings.TWOFACTOR_PAPER_CODES_WARN_RENEWAL + 1)

        self.device.counter = counter
        self.device.save()
        response = self.client.get(self.url)
        assert_exausted_warning(self, [self.device], response)


class DeviceRenameViewTestCase(DeviceViewsTestCaseBase):
    def setUp(self):
        super(DeviceRenameViewTestCase, self).setUp()
        self.url = reverse('device-rename', args=[self.device.id])

    def test_device_rename_get(self):
        response = self.client.get(self.url)

        tree = PyQuery(response.content)
        name_input = tree.find('input[name="name"]')
        self.assertEqual(name_input[0].value, 'foo')

    def test_device_rename_post(self):
        response = self.client.post(self.url, {'name': 'bar'})

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].endswith(reverse('device-list')))

        device = AuthenticationDevice.objects.get(id=self.device.id)
        self.assertEqual(device.name, 'bar')

    def test_device_rename_get_when_invalid_user(self):
        new_account = self.factory.make_account()
        self.client.logout()
        self.client.login(username=new_account.preferredemail.email,
                          password=DEFAULT_USER_PASSWORD)
        # post as new user
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 404)

    def test_device_rename_post_when_invalid_user(self):
        new_account = self.factory.make_account()
        self.client.logout()
        self.client.login(username=new_account.preferredemail.email,
                          password=DEFAULT_USER_PASSWORD)
        # post as new user
        response = self.client.post(self.url, {'name': 'bar'})
        self.assertEqual(response.status_code, 404)

    def test_device_rename_post_not_authed(self):
        self.mock_is_upgraded.return_value = False
        response = self.client.post(self.url, {'name': 'bar'})
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('twofactor'), response['Location'])

    def test_device_rename_get_not_fresh_twofactor(self):
        self.mock_is_fresh.return_value = False
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('twofactor'), response['Location'])


class DeviceRemovalViewTestCase(DeviceViewsTestCaseBase,
                                TwoFactorEnabledMixin):
    def setUp(self):
        super(DeviceRemovalViewTestCase, self).setUp()
        self.url = reverse('device-removal', args=[self.device.id])

    def test_device_removal_get_not_fresh_twofactor(self):
        self.mock_is_fresh.return_value = False
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('twofactor'), response['Location'])


class DeviceAdditionViewTestCase(DeviceViewsTestCaseBase):
    url = reverse('device-addition')

    def test_device_addition_get_not_fresh_twofactor(self):
        self.mock_is_fresh.return_value = False
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('twofactor'), response['Location'])


class DevicePrintViewTestCase(DeviceViewsTestCaseBase, TwoFactorEnabledMixin):
    def setUp(self):
        super(DevicePrintViewTestCase, self).setUp()
        self.url = reverse('device-print', args=[self.device.id])


class DeviceGenerateViewTestCase(DeviceViewsTestCaseBase,
                                 TwoFactorEnabledMixin):
    def setUp(self):
        super(DeviceGenerateViewTestCase, self).setUp()
        self.url = reverse('device-generate', args=[self.device.id])


class DeviceAuthenticationFailuretestCase(DeviceViewsTestCaseBase,
                                          TwoFactorEnabledMixin):
    url = reverse('twofactor')

    def setUp(self):
        super(DeviceAuthenticationFailuretestCase, self).setUp()
        self.account.twofactor_attempts = 7
        self.account.save()

    @mock.patch('webui.views.ui.logger')
    @mock.patch('webui.views.ui.auth')
    def test_too_many_attempts(self, mock_auth, mock_logger):
        with patch_settings(TWOFACTOR_MAX_ATTEMPTS=0):
            response = self.client.post(self.url, {'oath_token': '123456'})
            self.assertIn('Account suspended', response.content)
            self.assertTemplateUsed(response, 'account/suspended.html')

            account = Account.objects.get(id=self.account.id)
            self.assertEqual(account.status, AccountStatus.SUSPENDED)
            mock_auth.logout.assert_called_once_with(mock.ANY)
            mock_logger.warning.assert_called_once_with(
                mock.ANY, account.openid_identifier, account.id)

    def test_login_with_null_twofactor_attempts(self):
        account = Account.objects.get(id=self.account.id)
        account.twofactor_attempts = None
        account.save()

        self.client.post(self.url, {'oath_token': '123456'})
        account = Account.objects.get(id=self.account.id)
        self.assertEqual(account.twofactor_attempts, 1)

    def test_failed_login_increments_attempts(self):
        self.client.post(self.url, {'oath_token': '123456'})
        account = Account.objects.get(id=self.account.id)
        self.assertEqual(account.twofactor_attempts, 8)

    def test_successful_login_resets_attempts(self):
        with mock.patch('webui.views.ui.authenticate_device'):
            self.client.post(self.url, {'oath_token': '123456'})
            account = Account.objects.get(id=self.account.id)
            self.assertEqual(account.twofactor_attempts, 0)

    def test_invalid_post_increments_attempts(self):
        self.client.post(self.url, {})
        account = Account.objects.get(id=self.account.id)
        self.assertEqual(account.twofactor_attempts, 8)


class TwoFactorViewConcurrencyTestCase(TransactionTestCase):
    url = reverse('twofactor')

    def test_race_condition_when_twofactor_attempt(self):
        factory = SSOObjectFactory()
        account = factory.make_account(email='foo@test.com')
        device = factory.make_device(account, name='foo')

        @test_concurrently(2)
        @switches(TWOFACTOR=True)
        def fail_login():
            request = RequestFactory().post(self.url, {})
            request.user = account
            request.session = {}
            request.method = 'POST'
            view = TwoFactorView.as_view()

            def mocked(*args, **kwargs):
                import time
                time.sleep(0.1)

            # block for some time to ensure requests are concurrent
            mock_auth_device = mock.patch(
                'webui.views.ui.authenticate_device', mocked)
            with mock_auth_device:
                response = view(request)
            self.assertEqual(response.status_code, 200)

        fail_login()

        account = Account.objects.get(id=account.id)
        self.assertEqual(account.twofactor_attempts, 2)

        # cleanup
        device.delete()
        account.delete()
