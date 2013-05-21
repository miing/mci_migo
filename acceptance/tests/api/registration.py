from sst.actions import assert_equal, check_flags
from u1testutils import mail

from acceptance.apihelpers import get_api_client


check_flags('ALLOW_UNVERIFIED')

email_address = mail.make_unique_test_email_address()

client = get_api_client()

data = dict(
    email=email_address,
    password='Admin007',
    displayname='My Name',
    captcha_id='XYZ',
    captcha_solution='XYZ',
)

response = client.register(data)

assert_equal(response.status_code, 201)
assert 'application/json' in response.headers['content-type']

body = response.json()
assert 'openid' in body
assert 'href' in body
assert_equal(body['email'], email_address)
assert data['displayname'] in body['displayname']
assert_equal(body['status'], 'Active')
assert_equal(len(body['emails']), 1)
assert data['email'] in body['emails'][0]['href']
