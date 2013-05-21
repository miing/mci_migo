# This test ensures that the token sent via email can be used to verify
# the account.
from sst.actions import (
    assert_displayed,
    assert_title,
    click_button,
    exists_element,
    get_element,
    go_to,
    skip,
    write_textfield,
)
from u1testutils.sst import config

from acceptance import helpers, urls

if not exists_element(id='recaptcha_response_field'):
    skip("Test skipped - no captcha present")

config.set_base_url_from_env()
helpers.skip_unless_staging_or_production()

go_to(urls.NEW_ACCOUNT)
assert_title('Create account')

# explicitly don't set captcha
email_address = 'not_usual_test_email@test.com'
write_textfield('id_displayname', "My Name")
write_textfield('id_email', email_address)
write_textfield('id_password', "Admin007")
write_textfield('id_passwordconfirm', "Admin007")

# Even though the recaptcha field is ignored for our tests, we do want to
# verify that it is on the page. In response to Defect #839216 we click once
# before to ensure captcha is still displayed
click_button(get_element(name='continue'))
assert_displayed('recaptcha_response_field')
