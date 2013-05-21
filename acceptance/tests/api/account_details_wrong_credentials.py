from sst.actions import assert_equal
from u1testutils.sst import config

from ssoclient.v2 import ResourceNotFound
from acceptance import apihelpers, helpers


config.set_base_url_from_env()
client = apihelpers.get_api_client()
password = 'Admin007'


# Create an account
email_address = helpers.register_account(password=password)

# Login with the api to get a token
response = client.login(email=email_address, password=password,
                        token_name='test')
assert_equal(response.status_code, 201)
login_token = response.json()

# Use the token to fetch account details
client.account_details(login_token['openid'], login_token)

# Using the correct token but the wrong openid should cause a 404
try:
    client.account_details('wrongopenid', login_token)
    apihelpers.fail('should not get here')
except ResourceNotFound:
    pass

# Using the wrong token credentials will only return public data
login_token['token_key'] = 'something wrong'
response = client.account_details(login_token['openid'], login_token)
body = response.json()
assert 'openid' in body
assert 'status' not in body
