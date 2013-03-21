# 11) Check that the 'add email' form requires the user to put in a valid email
# address.

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
from u1testutils import mail
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls


config.set_base_url_from_env()

# Create and verify account A
helpers.register_account()

# Add and verify 2nd email
go_to(urls.EMAILS)
wait_for(assert_title_contains, "'s email addresses")
write_textfield('id_newemail', address)
click_button(get_element(name='continue'))

# Check the outcome
if valid:
    wait_for(assert_title, 'Validate your email address')
    mail.delete_msgs_sent_to(address)
else:
    wait_for(assert_title, 'Add an email')
    assert_text_contains(get_element(name='newemailform'), 'Invalid email.')
