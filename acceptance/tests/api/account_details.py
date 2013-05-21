from sst.actions import assert_equal
from u1testutils.sst import config

from acceptance import apihelpers

config.set_base_url_from_env()
client = apihelpers.get_api_client()

# Create an account
account, password = apihelpers.register_new_test_account()

# attempt anonymous access
anon_result = client.account_details(account['openid']).json()
assert 'verified' in anon_result
assert 'emails' not in anon_result
assert 'email' not in anon_result
assert 'displayname' not in anon_result
assert 'status' not in anon_result

# Login with the api to get a token
response = client.login(
    email=account['email'],
    password=password,
    token_name='test')
assert_equal(response.status_code, 201)
login_token = response.json()

# Use the token to fetch account details
result = client.account_details(login_token['openid'], login_token)
assert_equal(result.status_code, 200)
account_details = result.json()
assert_equal(account_details['status'], 'Active')
assert_equal(account_details['email'], account['email'])
assert 'verified' in account_details
assert 'emails' in account_details
assert 'displayname' in account_details
assert 'status' in account_details
