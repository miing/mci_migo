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
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import payclient
from django.conf import settings

import u1testutils.pay.environment
from piston_mini_client import auth


class APIClient(object):
    """API client helper for payment tests.

    It extends the PaymentServiceAPI to take the credentials from the Django
    configuration file and to make it easier for the tests to call the API
    methods.

    """

    def __init__(self, pay_server_url=None):
        pay_server_url = self._get_pay_server_url(pay_server_url)
        user = settings.PAY_API_USERNAME
        password = settings.PAY_API_PASSWORD
        basic_auth = auth.BasicAuthorizer(user, password)
        pay_api_url = '{0}/api/2.0/'.format(pay_server_url)
        self.client = payclient.PaymentServiceAPI(
            auth=basic_auth, service_root=pay_api_url)

    def _get_pay_server_url(self, pay_server_url=None):
        if pay_server_url is None:
            pay_server_url = u1testutils.pay.environment.get_pay_base_url()
        else:
            pay_server_url = pay_server_url.rstrip('/')
        return pay_server_url

    def add_new_credit_card(self, shop_id, user, credit_card, billing_address):
        """Add a new credit card through the Pay API.

        Keyword arguments:
        shop_id -- The identifier of the shop that will add the credit card.
        user -- The user that will have the new credit card. It must have the
            openid attribute.
        credit_card -- The credit card information. It must have the attributes
        card_type,  name_on_cad, card_number, ccv_number, expiration_month and
            expiration_year.
        billing_address -- The billing address for the card. It must have the
            attributes street_line1, state, country and postal_code. The
            country is the name of the country in english.

        """
        credit_card_request = payclient.CreditCardRequest.from_data_objects(
            shop_id, user.openid, credit_card, billing_address)
        return self.client.new_credit_card(data=credit_card_request)
