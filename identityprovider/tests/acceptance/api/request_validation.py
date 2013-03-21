from sst.actions import (
    assert_equal,
)

from identityprovider.tests.utils import authorization_header_from_token
from identityprovider.tests.acceptance.shared import urls
from identityprovider.tests.acceptance.shared.apihelpers import (
    get_api_client,
    register_new_test_account,
)

account, password = register_new_test_account()
client = get_api_client()

# missing params
result = client.validate_request()
assert_equal(result.json(), {'is_valid': False})

# invalid params
result = client.validate_request(http_url='foo', http_method='GET',
                                 authorization='1234567890')
assert_equal(result.json(), {'is_valid': False})

# correct params
url = 'http://example.com'
# obtain a token to sign the request
token = client.login(
    email=account['email'], password=password, token_name='test').json()
header = authorization_header_from_token(url, token,
                                         base_url=urls.get_base_url())
result = client.validate_request(http_url=url, http_method='GET',
                                 authorization=header['HTTP_AUTHORIZATION'])
assert_equal(result.json(), {'is_valid': True})
