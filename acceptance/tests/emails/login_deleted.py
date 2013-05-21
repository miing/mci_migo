# 4) Delete non-preferred email from account and attempt to login to the
# account
# using the deleted email
# Create new account and verified email
# Add second email and verify
# Delete second email
# Logout
# Login with deleted email

from sst.actions import (
    assert_title,
)
from u1testutils import mail
from u1testutils.sst import config

from acceptance import helpers


config.set_base_url_from_env()
PASSWORD = 'Admin007'

primary_email_id = mail.make_unique_test_email_address()
secondary_email_id = mail.make_unique_test_email_address()
helpers.register_account(primary_email_id, password=PASSWORD, verify=True)
vcode = helpers.add_email(secondary_email_id)
helpers.try_to_validate_email(secondary_email_id, vcode)
helpers.delete_email()
helpers.logout()
helpers.login(secondary_email_id, PASSWORD)
assert_title('Log in')
