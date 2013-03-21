from identityprovider.tests.acceptance.shared import helpers, urls

from sst import actions
from u1testutils import mail
from u1testutils.sst import config
from u1testutils.sst.sso.utils import mail as sso_mail


config.set_base_url_from_env()

# Create a new account and login
helpers.login_or_register_account()

# Add a new email address
# (adding an email waits for the verification email to arrive and deletes
#  that email - but by default does *not* verify the email.)
new_email = mail.make_unique_test_email_address()
helpers.add_email(new_email)

# Request resending of verification email
actions.go_to(urls.EMAILS)

link_css = 'a[data-qa-id="_verify_unverified_%s"]' % new_email
verify_unverified_new_email_link = actions.get_element_by_css(link_css)

actions.click_link(verify_unverified_new_email_link)

# Check the email has arrived
code = sso_mail.get_verification_code_for_address(new_email)

# Use the code
actions.write_textfield(actions.get_element(tag='input', type='text'), code)
actions.click_button(actions.get_element(tag='button', text='Confirm'))
actions.click_button(actions.get_element(tag='button', name='continue'))

# we should be redirected back to '/'
actions.assert_url('/')
