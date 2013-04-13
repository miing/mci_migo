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

import uuid

import payclient.data


class CreditCard(payclient.data.CreditCard):
    """Extends the payclient CreditCard to add factory methods for testing."""

    @classmethod
    def make_test_visa_card(cls, unique_id=None):
        if unique_id is None:
            unique_id = str(uuid.uuid1())
        card_type = 'Visa'
        name_on_card = 'Test name {0}'.format(unique_id)
        card_number = '4111111111111111'
        ccv_number = '123'
        expiration_month = '12'
        expiration_year = '2026'
        return cls(card_type, name_on_card, card_number, ccv_number,
                   expiration_month, expiration_year)


class Address(payclient.data.Address):
    """Extends the payclient Address to add factory methods for testing.

    It also receives a country name in the constructor, instead of a country
    code, receives the street_line2 and city, and concatenates street_line1
    and street_line2 in the street attribute that the parent class receives.

    """

    def __init__(self, street_line1, street_line2, city, state, postal_code,
                 country):
        self.country = country
        self.street_line1 = street_line1
        self.street_line2 = street_line2
        self.city = city
        street = '{0}\n{1}'.format(street_line1, street_line2)
        super(Address, self).__init__(
            street, state, postal_code, self._get_country_code())

    @classmethod
    def make_unique(cls, unique_id=None):
        if unique_id is None:
            unique_id = str(uuid.uuid1())
        street_line1 = "Test street line 1 {0}".format(unique_id)
        street_line2 = "Test street line 2 {0}".format(unique_id)
        city = "Test city {0}".format(unique_id)
        state = "Test state {0}".format(unique_id)
        postal_code = "12345"
        country = "United States"
        return cls(
            street_line1, street_line2, city, state, postal_code, country)

    def _get_country_code(self):
        # TODO add more?
        country_data = {'United States': 'US'}
        return country_data.get(self.country)
