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

import mock
import payclient

import u1testutils.django
from u1testutils.pay import client
from u1testutils.pay import data as pay_data
from u1testutils.sso import data as sso_data


class APIClientTestCase(unittest.TestCase):

    def test_get_api_client(self):
        api_client = client.APIClient()
        self.assertTrue(
            isinstance(api_client.client, payclient.PaymentServiceAPI))

    def test_get_api_client_with_default_url(self):
        api_client = client.APIClient()
        self.assertEquals(
            api_client.client._service_root, 'http://localhost:8000/api/2.0/')

    def test_get_api_client_with_settings_url(self):
        with u1testutils.django.patch_settings(
                PAY_SERVER_URL='http://settings.pay.local:8000'):
            api_client = client.APIClient()
        self.assertEquals(
            api_client.client._service_root,
            'http://settings.pay.local:8000/api/2.0/')

    def test_get_api_client_with_argument_url(self):
        pay_server_url = 'http://argument.pay.local:8000'
        api_client = client.APIClient(pay_server_url)
        self.assertEquals(
            api_client.client._service_root,
            'http://argument.pay.local:8000/api/2.0/')

    def test_get_api_client_with_argument_url_and_trailing_slash(self):
        pay_server_url = 'http://argument.pay.local:8000/'
        api_client = client.APIClient(pay_server_url)
        self.assertEquals(
            api_client.client._service_root,
            'http://argument.pay.local:8000/api/2.0/')


class CreditCardAPIClientTestCase(unittest.TestCase):

    def setUp(self):
        self.user = sso_data.User(
            full_name='test', email='test', password='test', openid='test')
        self.credit_card = pay_data.CreditCard.make_test_visa_card()
        self.billing_address = pay_data.Address.make_unique()

    def test_new_credit_card_added(self):
        shop_id = 'TEST'
        api_client = client.APIClient()
        with mock.patch('payclient.PaymentServiceAPI.new_credit_card') \
                as mock_api_call:
            api_client.add_new_credit_card(
                shop_id, self.user, self.credit_card, self.billing_address)
        mock_api_call.assert_called_with(
            data=payclient.CreditCardRequest.from_data_objects(
                shop_id, self.user.openid, self.credit_card,
                self.billing_address))
