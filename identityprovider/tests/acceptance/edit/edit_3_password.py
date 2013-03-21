# This test ensures that changing the password works (and the user can
# subsequently login with the new password but not the old).
from sst.actions import (
    assert_title,
    click_button,
    get_element,
    go_to,
    write_textfield,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls


config.set_base_url_from_env()

# Create an account with a specific password.
initial_password = "fo87sFnh"
email_address = helpers.register_account(displayname="Fred Jones",
                                         password=initial_password)

# Change the password and save.
go_to(urls.EDIT)
new_password = "g8o78Fgn"
assert_title("Fred Jones's details")
write_textfield('id_password', new_password)
write_textfield('id_passwordconfirm', new_password)
click_button(get_element(name='update'))

# Now try logging in with the old password - which fails.
helpers.logout()
helpers.login(email_address, initial_password)
assert_title("Log in")

# But logging in with the new password works.
helpers.login(email_address, new_password)
assert_title("Fred Jones's details")
