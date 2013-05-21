# A new password can be set using the email link sent via the
# forgot_password functionality.

from acceptance import helpers, urls

from sst.actions import (
    assert_element,
    assert_title,
    click_button,
    click_link,
    get_element,
    go_to,
    write_textfield,
    wait_for,
)
from u1testutils.sso import mail
from u1testutils.sst import config


config.set_base_url_from_env()

edit_account_anchor = {'data-qa-id': 'edit_account'}

# Create an account and logout.
email_address = helpers.register_account(displayname="Fred Jones", verify=True)
helpers.logout()

# Request the password reset.
go_to(urls.HOME)
assert_title('Log in')
click_link('forgotpw-link')
write_textfield('id_email', email_address)
# Even though the recaptcha field is ignored for our tests, we do
# want to verify that it is on the page.
write_textfield('recaptcha_response_field', 'ignored')
click_button(get_element(name='continue'))

assert_element(**{'data-qa-id': 'forgot_password_step_2'})

# Fetch and verify the confirmation link.
link = mail.get_verification_link_for_address(email_address)
go_to(link)

# Reset the password and verify that we're logged in.
assert_title('Reset password')
write_textfield('id_password', "Other008")
write_textfield('id_passwordconfirm', "Other008")
click_button(get_element(name='continue'))
assert_element(**edit_account_anchor)

# Now confirm that we can log in with the new password.
helpers.logout()
helpers.login(email_address, 'Other008')
wait_for(assert_element, **edit_account_anchor)
