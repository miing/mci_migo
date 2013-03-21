from sst.actions import (
    assert_equal,
    assert_not_equal,
)
from u1testutils.sst import config

from ssoclient.v2 import InvalidCredentials
from identityprovider.tests.acceptance.shared import apihelpers, helpers


config.set_base_url_from_env()
client = apihelpers.get_api_client()
password = 'Admin007'


# Create an account
email_address = helpers.register_account(password=password)

# Attempt to login via the api with the wrong password
try:
    client.login(email=email_address, password='wrong password',
                 token_name='test')
    apihelpers.fail('Logging in with wrong password should fail')
except InvalidCredentials:
    # this is expected
    pass

# Try to login again, with the right password
response = client.login(email=email_address, password=password,
                        token_name='test')
assert_equal(response.status_code, 201)
body1 = response.json()

# Logging in again with the same token name should get the same response
# except that token update time changed
response = client.login(email=email_address, password=password,
                        token_name='test')
body2 = response.json()
body1.pop('date_updated')
body2.pop('date_updated')
assert_equal(body1, body2)

# Using a different token name should get a different token
response = client.login(email=email_address, password=password,
                        token_name='a-different-test')
body3 = response.json()
assert_equal(body3['token_name'], 'a-different-test')
assert_not_equal(body3['token_key'], body1['token_key'])
assert_not_equal(body3['token_secret'], body1['token_secret'])
