# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from identityprovider.tests.utils import SSOBaseTestCase

from webui.views import utils


class RedirectionURLForTokenTestCase(SSOBaseTestCase):

    def test_if_token_is_none(self):
        url = utils.redirection_url_for_token(None)
        self.assertEqual(url, "/")

    def test_if_token_is_not_none(self):
        token = "ABCDEFGH" * 2
        url = utils.redirection_url_for_token(token)
        self.assertEqual(url, "/%s/+decide" % token)
