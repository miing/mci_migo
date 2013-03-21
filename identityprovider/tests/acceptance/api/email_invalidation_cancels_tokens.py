from sst.actions import (
    assert_equal,
    assert_title_contains,
    check_flags,
    click_button,
    get_element,
    go_to,
    write_textfield,
)
from u1testutils import mail
from u1testutils.sst import config
from u1testutils.sst.sso.utils import mail as sso_mail

from identityprovider.tests.acceptance.shared import (
    apihelpers,
    helpers,
    urls,
)

check_flags('allow_unverified')


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

# Add a new email
go_to(urls.EMAILS)
assert_title_contains("email addresses")
new_email = mail.make_unique_test_email_address()
write_textfield('id_newemail', new_email)
click_button(get_element(name='continue'))

# Find the invalidation link
link = sso_mail.get_invalidation_link_for_address(new_email)
assert link is not None, 'Invalidation link should not be None.'

# Invalidate the new email address
go_to(link)
assert_title_contains('Email invalidation')

click_button(get_element(name='invalidate'))
assert_title_contains('Email invalidated')

# The login token should now be invalid, meaning we can only get public data
response = client.account_details(login_token['openid'], login_token)
body = response.json()
assert 'openid' in body
assert 'status' not in body
