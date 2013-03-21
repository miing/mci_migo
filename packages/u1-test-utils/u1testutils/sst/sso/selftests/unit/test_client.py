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

from mock import Mock, patch

from u1testutils.sst.sso import client, data
from ssoclient.v2 import V2ApiClient


class ClientTestCase(unittest.TestCase):

    base_namespace = 'u1testutils.sst.sso.client'

    def test_get_api_client(self):
        mock_get_base_url = Mock(return_value='http://localhost:8000')
        with patch(self.base_namespace + '.environment.get_sso_base_url',
                   mock_get_base_url):
            api_client = client.get_api_client()

        self.assertTrue(isinstance(api_client, V2ApiClient))
        self.assertEqual(api_client.session.endpoint,
                         'http://localhost:8000/api/v2/')

    def test_get_account_openid(self):
        mock_login = Mock()
        mock_login.return_value.json.return_value = {
            'consumer_key': 'oid1234',
            'consumer_secret': 'consumer-secret',
            'token_name': 'foo',
            'token_key': 'token-key',
            'token_secret': 'token-secret',
        }

        with patch(self.base_namespace + '.V2ApiClient.login', mock_login):
            openid = client.get_account_openid('email', 'password',
                                               'token_name')

        self.assertEqual(openid, 'oid1234')

    def test_get_account_openid_wrong_credentials(self):
        mock_login = Mock()
        mock_login.return_value.json.return_value = {
            "code": "INVALID_CREDENTIALS",
            "message": "Your email/password isn't correct.",
            "extra": {}
        }

        with patch(self.base_namespace + '.V2ApiClient.login', mock_login):
            openid = client.get_account_openid('email', 'password',
                                               'token_name')

        self.assertIsNone(openid)

    def test_create_new_account_created(self):
        user = data.User.make_from_configuration()
        mock_register = Mock()
        mock_register.return_value.status_code = 201
        client_register = self.base_namespace + '.V2ApiClient.register'
        with patch(client_register, mock_register):
            created = client.create_new_account(user)
        self.assertTrue(created)

    def test_create_new_account_failed(self):
        user = data.User.make_from_configuration()
        mock_register = Mock()
        mock_register.return_value.status_code = 400
        client_register = self.base_namespace + '.V2ApiClient.register'
        with patch(client_register, mock_register):
            created = client.create_new_account(user)
        self.assertFalse(created)
