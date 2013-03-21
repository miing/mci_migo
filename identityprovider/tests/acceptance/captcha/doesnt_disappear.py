# This test ensures that the token sent via email can be used to verify
# the account.
from sst.actions import (
    assert_element,
    assert_title,
    click_button,
    get_element,
    go_to,
    write_textfield,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls


helpers.skip_unless_staging_or_production()

config.set_base_url_from_env()

go_to(urls.NEW_ACCOUNT)
assert_title('Create account')

email_address = 'dont_trigger_catpcha_whitelist@canonical.com'
write_textfield('id_displayname', "My Name")
write_textfield('id_email', email_address)
write_textfield('id_password', "Admin007")
write_textfield('id_passwordconfirm', "Admin007")
# Even though the recaptcha field is ignored for our tests, we do
# want to verify that it is on the page.
write_textfield('recaptcha_response_field', 'wrong answer')
click_button(get_element(name='continue'))

# Make sure we were returned to the form, for not answering the
# Captcha correctly.
assert_title('Create account')

assert_element(id='recaptcha_response_field')
