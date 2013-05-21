# Copyright 2012, 2013 Canonical Ltd.
# This software is licensed under the GNU Affero General Public License
# version 3 (see the file LICENSE).

from oath import hotp

from acceptance import base


class TestBackupDeviceWarning(base.SSTTestCaseWithLogIn):

    def navigate_to_page(self):
        """Go to the YourAuthenticationDevices page.

        It will be accessible for the tests from the page attribute.

        """
        # 'start' is the base YourAccount page object.
        start = super(TestBackupDeviceWarning, self).navigate_to_page()
        return start.subheader.go_to_authentication_devices()

    def test_no_warning_before_adding_device(self):
        self.assertFalse(self.page.is_warning_displayed())

    def test_warning_displayed_for_single_device(self):
        your_auth_devices_page = self.add_device(
            self.page, 'Test device warning')
        self.assertTrue(your_auth_devices_page.is_warning_displayed())

    def test_warning_removed_after_second_device_added(self):
        your_auth_devices_page = self.add_device(
            self.page, 'Test device warning 1')
        your_auth_devices_page = self.add_device(
            your_auth_devices_page, 'Test device warning 2')
        self.assertFalse(your_auth_devices_page.is_warning_displayed())

    def test_warning_returns_after_second_device_deleted(self):
        your_auth_devices_page = self.add_device(
            self.page, 'Test device warning 1')
        your_auth_devices_page = self.add_device(
            your_auth_devices_page, 'Test device warning 2')
        rm_device_page = your_auth_devices_page.delete_authentication_device()
        your_auth_devices_page = rm_device_page.confirm_delete_device()
        self.assertTrue(your_auth_devices_page.is_warning_displayed())

    def add_device(self, auth_devices_page, device_name):
        add_new_device_page = auth_devices_page.add_new_authentication_device()
        add_generic_device_page = add_new_device_page.add_generic_device()
        aes_key = add_generic_device_page.get_key()
        one_time_password = hotp.hotp(aes_key, 0)
        return add_generic_device_page.add_device(
            device_name, one_time_password)
