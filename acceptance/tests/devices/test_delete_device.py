# Copyright 2012, 2013 Canonical Ltd.
# This software is licensed under the GNU Affero General Public License
# version 3 (see the file LICENSE).

from oath import hotp

from acceptance import base


class TestDeleteDevice(base.SSTTestCaseWithLogIn):

    def navigate_to_page(self):
        """Navigate to DeleteAuthenticationDevices with a device added."""
        # Start from where the base test case leaves us, the YourAccount page.
        start = super(TestDeleteDevice, self).navigate_to_page()
        auth_devices_page = start.subheader.go_to_authentication_devices()
        return self.add_device(auth_devices_page)

    def test_device_deletion(self):
        your_auth_devices = self.page.confirm_delete_device()
        self.assertEqual(
            your_auth_devices.get_devices(), [])

    def test_cancel_device_deletion(self):
        your_auth_devices = self.page.cancel()
        self.assertEqual(
            your_auth_devices.get_devices(), ['Test device delete'])

    def add_device(self, auth_devices_page):
        test_device_page = auth_devices_page.add_new_authentication_device()
        add_device_page = test_device_page.add_generic_device()
        aes_key = add_device_page.get_key()
        one_time_password = hotp.hotp(aes_key, 0)
        auth_devices_page = add_device_page.add_device(
            'Test device delete', one_time_password)
        return auth_devices_page.delete_authentication_device()
