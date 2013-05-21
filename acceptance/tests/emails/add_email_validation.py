# 9) Check that a missing value does not allow submission of the 'add email'
# form.'

from sst.actions import (
    assert_text_contains,
    assert_title,
    assert_title_contains,
    click_button,
    get_element,
    go_to,
    wait_for,
    write_textfield,
)
from u1testutils.sst import config

from acceptance import helpers, urls


config.set_base_url_from_env()

# Create and verify account A
helpers.register_account()

# Add and verify 2nd email
go_to(urls.EMAILS)
wait_for(assert_title_contains, "'s email addresses")
write_textfield('id_newemail', '')
click_button(get_element(name='continue'))

# Check for error message
wait_for(assert_title, 'Add an email')
assert_text_contains(get_element(name='newemailform'), 'Required field.')
