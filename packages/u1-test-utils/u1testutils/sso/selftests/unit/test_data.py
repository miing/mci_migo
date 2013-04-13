# -*- coding: utf-8 -*-

# Copyright 2012, 2013 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 3, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/

import unittest

from django.conf import settings
from mock import patch

from u1testutils.sso import data


class DataTestCase(unittest.TestCase):

    def test_make_exising_user(self):
        # The DJANGO_SETTINGS_MODULE is set by the test fab task.
        user = data.User.make_from_configuration()

        self.assertEqual(user.full_name, settings.SSO_TEST_ACCOUNT_FULL_NAME)
        self.assertEqual(user.email, settings.SSO_TEST_ACCOUNT_EMAIL)
        self.assertEqual(user.password, settings.SSO_TEST_ACCOUNT_PASSWORD)


class UserTestCase(unittest.TestCase):

    def setUp(self):
        self.user = data.User.make_from_configuration()

    def tert_default_openid(self):
        self.assertIsNone(self.user._openid)

    def test_openid_for_valid_account(self):
        with patch('u1testutils.sso.data.client') as mock_client:
            mock_client.get_account_openid.return_value = 'foo1234'

            self.assertEqual(self.user.openid, 'foo1234')
            self.assertEqual(self.user._openid, 'foo1234')

    def test_openid_for_invalid_account(self):
        with patch('u1testutils.sso.data.client') as mock_client:
            mock_client.get_account_openid.return_value = None

            self.assertEqual(self.user.openid, None)
            self.assertIsNone(self.user._openid, None)
