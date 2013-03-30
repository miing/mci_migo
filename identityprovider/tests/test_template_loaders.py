# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from gargoyle.testutils import switches
from django.test import TestCase

from identityprovider.template_loaders.brand import Loader


class BrandLoaderTestCase(TestCase):

    @switches(BRAND_UBUNTUONE=True)
    def test_feature_switch_for_u1(self):
        l = Loader()

        result = l.get_template_sources('registration/login.html', [
            '/foo/bar',
        ])

        self.assertEqual(['/foo/bar/ubuntuone/registration/login.html'],
                         list(result))

    @switches(BRAND_LAUNCHPAD=True)
    def test_feature_switch_for_lp(self):
        l = Loader()

        result = l.get_template_sources('registration/login.html', [
            '/foo/bar',
        ])

        self.assertEqual(['/foo/bar/launchpad/registration/login.html'],
                         list(result))
