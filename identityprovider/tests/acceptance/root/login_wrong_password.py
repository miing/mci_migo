# 2) Check you cannot login with the wrong password, then click the 'Forgot
# Password' and ensure it is prepopulated

from sst.actions import (
    assert_text_contains,
    assert_title,
    click_link,
    get_element,
    wait_for,
)
from u1testutils import mail
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers


config.set_base_url_from_env()

primary_email_id = mail.make_unique_test_email_address()
secondary_email_id = mail.make_unique_test_email_address()
helpers.register_account(primary_email_id)

helpers.logout()
helpers.login(primary_email_id, 'BOGUS')
assert_text_contains('content', "Password didn't match")
click_link('forgotpw-link')
wait_for(assert_title, 'Reset password')
assert get_element(id='id_email').get_attribute('value') == primary_email_id
