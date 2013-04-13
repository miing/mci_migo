# -*- coding: utf-8 -*-

# Copyright 2013 Canonical Ltd.
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

from u1testutils.django import patch_settings


class PatchSettingsTestCase(unittest.TestCase):

    def test_patch_settings_using_as_context_manager(self):
        assert not settings.DEBUG
        with patch_settings(DEBUG=True):
            self.assertTrue(settings.DEBUG)
        self.assertFalse(settings.DEBUG)

    def test_patch_settings_start_stop(self):
        assert not settings.DEBUG
        p = patch_settings(DEBUG=True)
        p.start()
        self.assertTrue(settings.DEBUG)
        p.stop()
        self.assertFalse(settings.DEBUG)

    def test_patch_settings_not_available_setting(self):
        marker = object()
        assert getattr(settings, 'NOT_AVAILABLE', marker) is marker
        with patch_settings(NOT_AVAILABLE=True):
            self.assertTrue(settings.NOT_AVAILABLE)
        self.assertIs(getattr(settings, 'NOT_AVAILABLE', marker), marker)
