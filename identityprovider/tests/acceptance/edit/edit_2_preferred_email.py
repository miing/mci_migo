# This test ensures that changing the preferred email for an account works.
from sst.actions import (
    assert_dropdown_value,
    assert_title,
    click_button,
    get_element,
    go_to,
    set_dropdown_value,
)
from u1testutils import mail
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls


config.set_base_url_from_env()

# Create an account with multiple emails.
email_address = helpers.register_account(displayname="Fred Jones", verify=True)
other_email_address = mail.make_unique_test_email_address()
helpers.add_email(other_email_address, verify=True)

# Verify the current preferred email and change it.
go_to(urls.EDIT)
assert_title("Fred Jones's details")
assert_dropdown_value('id_preferred_email', email_address)
set_dropdown_value('id_preferred_email', other_email_address)
click_button(get_element(name='update'))

# Verify that it was changed (we re-load the page to be sure it's not
# some unexpected validation error):
go_to(urls.EDIT)
assert_title("Fred Jones's details")
assert_dropdown_value('id_preferred_email', other_email_address)

# XXX Julien would also like this test to trigger an email being sent so
# we can verify that the email is actually sent to the preferred
# address.
