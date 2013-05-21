# Copyright 2012, 2013 Canonical Ltd.
# This software is licensed under the GNU Affero General Public License
# version 3 (see the file LICENSE).

import unittest

import sst

from acceptance import base


@unittest.skipIf('paper_device' not in sst.config.flags,
                 'Paper device is not enabled.')
class TestGeneratePaperCodes(base.SSTTestCaseWithLogIn):

    def navigate_to_page(self):
        """Go to the PaperDevice page.

        It will be accessible for the tests from the page attribute.

        """
        # 'start' is the base YourAccount page object.
        start = super(TestGeneratePaperCodes, self).navigate_to_page()
        auth_devices = start.subheader.go_to_authentication_devices()
        add_device_page = auth_devices.add_new_authentication_device()
        return add_device_page.add_paper_device()

    def test_generate_paper_codes(self):
        # Get the first code which we will invalidate
        old_code = self.page.get_first_code()
        new_codes_page = self.page.generate_new_codes()
        paper_device_page = new_codes_page.confirm_new_codes()
        new_code = paper_device_page.get_first_code()
        self.assertNotEqual(old_code, new_code)

    def test_cancel_generating_paper_codes(self):
        # Get the first code which should remain after cancel
        the_code = self.page.get_first_code()
        new_codes_page = self.page.generate_new_codes()
        paper_device_page = new_codes_page.cancel()
        the_same_code = paper_device_page.get_first_code()
        self.assertEqual(the_code, the_same_code)
