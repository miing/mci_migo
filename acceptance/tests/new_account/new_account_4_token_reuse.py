# The token generated when creating a new account should not be able to
# be used with other email addresses.
from sst.actions import (
    assert_title_contains,
    click_button,
    exists_element,
    get_element,
    skip,
    sleep,
    write_textfield,
    wait_for,
)
from sst import config as sst_config
from u1testutils import mail
from u1testutils.sst import config

from acceptance import helpers

if 'allow_unverified' in sst_config.flags:
    skip("allow_unverified means this test is irrelevant")

config.set_base_url_from_env()

email_address_for_token = mail.make_unique_test_email_address()
token = helpers.register_account(email_address_for_token)

# Now we create a second account and try to use the original
# verification code/token.
another_email = mail.make_unique_test_email_address()
helpers.logout()
helpers.register_account(another_email, verify=False)
write_textfield(get_element(name='confirmation_code'), token)
sleep(1)  # we have no idea why this is needed but bad things happen if omitted
click_button(get_element(css_class='btn'))

# We are still on the 'Enter confirmation code' page, and have been told
# that the confirmation code we used is unknown.
wait_for(assert_title_contains, 'Enter confirmation code')
exists_element(id='confirmation_code_error')
