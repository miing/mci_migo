# This test ensures that a new account cannot be created without the
# required fields.
from sst.actions import (
    assert_url,
    click_button,
    get_element,
    go_to,
)
from u1testutils import mail
from u1testutils.sst import config

import urls
import helpers


config.set_base_url_from_env()

email_address = mail.make_unique_test_email_address()

# Without an email the new account cannot be created.
go_to(urls.NEW_ACCOUNT)
helpers.fill_registration_form("")
click_button(get_element(name='continue'))
assert_url(urls.NEW_ACCOUNT)

# Without a display name a new account cannot be created.
go_to(urls.NEW_ACCOUNT)
helpers.fill_registration_form(email_address, displayname="")
click_button(get_element(name='continue'))
assert_url(urls.NEW_ACCOUNT)

# Without either password an account cannot be created.
go_to(urls.NEW_ACCOUNT)
helpers.fill_registration_form(email_address, passwordconf="")
click_button(get_element(name='continue'))
assert_url(urls.NEW_ACCOUNT)
go_to(urls.NEW_ACCOUNT)
helpers.fill_registration_form(email_address, password="")
click_button(get_element(name='continue'))
assert_url(urls.NEW_ACCOUNT)
