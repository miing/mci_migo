# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.conf import settings
from mock import patch

from identityprovider import urls
from identityprovider.tests.utils import SSOBaseTestCase


class TestingViewsTestCase(SSOBaseTestCase):
    def test_error_debug(self):
        with patch.multiple(settings, DEBUG=True):
            reload(urls)
            self.assertRaises(FloatingPointError, self.client.get, '/error')

    def test_error_no_debug(self):
        with patch.multiple(settings, DEBUG=False):
            reload(urls)
            response = self.client.get('/error')
            self.assertEqual(response.status_code, 404)
