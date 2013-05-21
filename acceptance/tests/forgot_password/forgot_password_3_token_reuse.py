# A password request token/link can only be used once to reset the
# password.
from sst.actions import (
    assert_element,
    assert_title,
    click_button,
    get_element,
    go_to,
    write_textfield,
    wait_for,
)
from u1testutils.sso import mail
from u1testutils.sst import config

from acceptance import helpers


config.set_base_url_from_env()

# Register a new account and request a password reset.
email_address = helpers.register_account(displayname="Fred Jones", verify=True)
helpers.request_password_reset(email_address)

# Fetch and verify the confirmation code.
link = mail.get_verification_link_for_address(email_address)
go_to(link)

# Reset the password and verify that we're logged in.
assert_title('Reset password')
write_textfield('id_password', "Admin007")
write_textfield('id_passwordconfirm', "Admin007")
click_button(get_element(name='continue'))
assert_element(**{'data-qa-id': 'edit_account'})

# Now try to use the link a second time.
helpers.logout()
go_to(link)
wait_for(assert_title, "Unauthorized confirmation code")
