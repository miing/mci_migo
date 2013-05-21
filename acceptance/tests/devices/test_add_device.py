# Copyright 2012, 2013 Canonical Ltd.
# This software is licensed under the GNU Affero General Public License
# version 3 (see the file LICENSE).

import unittest

import sst

from oath import hotp

from acceptance import base


def navigate_to_device_add_page(start):
    # 'start' is the base YourAccount page object.
    authentication_devices = start.subheader.go_to_authentication_devices()
    return authentication_devices.add_new_authentication_device()


class TestAddDevice(base.SSTTestCaseWithLogIn):

    def navigate_to_page(self):
        """Go to the AddNewAuthenticationDevice page.

        It will be accessible for the tests from the page attribute.

        """
        return navigate_to_device_add_page(
            super(TestAddDevice, self).navigate_to_page())

    def test_cancel_device_addition(self):
        your_authentication_devices = self.page.cancel()
        self.assertEqual(your_authentication_devices.get_devices(), [])

    def test_default_device(self):
        self.assertEqual(
            self.page.get_selected_device(),
            'type_google')

    @unittest.skipIf('paper_device' not in sst.config.flags,
                     'Paper device is not enabled.')
    def test_paper_device_enabled(self):
        self.assertTrue(
            self.page.is_paper_device_displayed())

    @unittest.skipIf('paper_device' in sst.config.flags,
                     'Paper device is not disabled.')
    def test_paper_device_disabled(self):
        self.assertFalse(
            self.page.is_paper_device_displayed())


class TestAddGenericDevice(base.SSTTestCaseWithLogIn):

    def navigate_to_page(self):
        """Go to the AddGenericDevice page.

        It will be accessible for the tests from the page attribute.

        """
        add_device_page = navigate_to_device_add_page(
            super(TestAddGenericDevice, self).navigate_to_page())
        return add_device_page.add_generic_device()

    def test_open_add_generic_device_page(self):
        name, one_time_password = self.page.get_form_values()
        self.assertEqual(name, 'Authentication device')
        self.assertEqual(one_time_password, '')
        name_error, one_time_password_error = self.page.get_form_errors()
        self.assertEqual(name_error, None)
        self.assertEqual(one_time_password_error, None)

    def test_cancel_generic_device_addition(self):
        your_authentication_devices = self.page.cancel()
        self.assertEqual(your_authentication_devices.get_devices(), [])

    def test_add_generic_device_with_errors(self):
        # Test with default name and wrong password.
        add_device = self.page.add_device_with_errors(
            name=None, one_time_password='some invalid key')
        name_error, one_time_password_error = add_device.get_form_errors()
        self.assertEqual(name_error, None)
        self.assertEqual(
            one_time_password_error,
            'Please enter a 6-digit or 8-digit one-time password.')
        # Test with missing name and wrong password.
        add_device = add_device.add_device_with_errors(
            name='', one_time_password=None)
        name_error, one_time_password_error = add_device.get_form_errors()
        self.assertEqual(name_error, 'This field is required.')
        self.assertEqual(
            one_time_password_error,
            'Please enter a 6-digit or 8-digit one-time password.')
        # Test with missing name, correct password.
        aes_key = add_device.get_key()
        valid_otp = hotp.hotp(aes_key, 0)
        add_device = add_device.add_device_with_errors(
            name=None, one_time_password=valid_otp)
        name_error, one_time_password_error = add_device.get_form_errors()
        self.assertEqual(name_error, 'This field is required.')
        self.assertEqual(one_time_password_error, None)

    def test_add_generic_device(self):
        aes_key = self.page.get_key()
        one_time_password = hotp.hotp(aes_key, 0)
        your_authentication_devices = self.page.add_device(
            'Test generic device', one_time_password)
        self.assertEqual(
            your_authentication_devices.get_devices(), ['Test generic device'])


class TestAddGoogleDevice(base.SSTTestCaseWithLogIn):

    def navigate_to_page(self):
        """Go to the AddGoogleDevice page.

        It will be accessible for the tests from the page attribute.

        """
        add_device_page = navigate_to_device_add_page(
            super(TestAddGoogleDevice, self).navigate_to_page())
        return add_device_page.add_google_device()

    def test_add_google_device(self):
        aes_key = self.page.get_key(self.user.email)
        one_time_password = hotp.hotp(aes_key, 0)
        your_authentication_devices = self.page.add_device(
            'Test Google device', one_time_password)
        self.assertEqual(
            your_authentication_devices.get_devices(), ['Test Google device'])


class TestAddYubikeyDevice(base.SSTTestCaseWithLogIn):

    def navigate_to_page(self):
        """Go to the AddYubikeyDevice page.

        It will be accessible for the tests from the page attribute.

        """
        add_device_page = navigate_to_device_add_page(
            super(TestAddYubikeyDevice, self).navigate_to_page())
        return add_device_page.add_yubikey_device()

    def test_add_yubikey_device(self):
        self.page.assert_warning()
        aes_key = self.page.get_key()
        one_time_password = hotp.hotp(aes_key, 0)
        your_authentication_devices = self.page.add_device(
            'Test Yubikey device', one_time_password)
        self.assertEqual(
            your_authentication_devices.get_devices(), ['Test Yubikey device'])


@unittest.skipIf('paper_device' not in sst.config.flags,
                 'Paper device is not enabled.')
class TestAddPaperDevice(base.SSTTestCaseWithLogIn):

    def navigate_to_page(self):
        """Go to the PaperDevice page.

        It will be accessible for the tests from the page attribute.

        """
        add_device_page = navigate_to_device_add_page(
            super(TestAddPaperDevice, self).navigate_to_page())
        return add_device_page.add_paper_device()

    def test_add_paper_device(self):
        self.page.assert_codes_present()
        self.page.assert_print_button_visible()
        your_auth_devices = self.page.go_back_to_device_list()
        self.assertEqual(
            your_auth_devices.get_devices(), ['Printable Backup Codes'])
