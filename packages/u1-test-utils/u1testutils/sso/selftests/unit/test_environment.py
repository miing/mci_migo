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
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import unittest

from django.conf import settings

from u1testutils.sso import environment


class EnvironmentTestCase(unittest.TestCase):

    def test_get_sso_base_url_from_settings(self):
        settings.OPENID_SSO_SERVER_URL = 'http://foo'

        try:
            base_url = environment.get_sso_base_url()
            self.assertEqual(base_url, 'http://foo')
        finally:
            del settings.OPENID_SSO_SERVER_URL

    def test_get_sso_base_url_from_settings_with_stripping(self):
        settings.OPENID_SSO_SERVER_URL = 'http://foo/'

        try:
            base_url = environment.get_sso_base_url()
            self.assertEqual(base_url, 'http://foo')
        finally:
            del settings.OPENID_SSO_SERVER_URL

    def test_get_sso_base_url_from_default(self):
        base_url = environment.get_sso_base_url()
        self.assertEqual(base_url, 'http://localhost:8000')
