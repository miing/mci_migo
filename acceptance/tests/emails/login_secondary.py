# 5) Ensure you can login with a non-preferred email address associated to the
# account.  Create new account and verified email
# Add second email and verify
# Logout
# Login with secondary email
from sst import config as sst_config
from sst.actions import (
    assert_element,
    fails,
    wait_for,
)

from u1testutils import mail
from u1testutils.sst import config

from acceptance import helpers


config.set_base_url_from_env()
NAME = 'Some Name'
PASSWORD = 'Admin007'

# Register the primary account.
primary_email_id = mail.make_unique_test_email_address()
helpers.register_account(primary_email_id, NAME, PASSWORD)

edit_account_anchor = {'data-qa-id': 'edit_account'}

# Register a secondary email, but don't verify.
secondary_email_id = mail.make_unique_test_email_address()
vcode = helpers.add_email(secondary_email_id)

# Attempt to login with the unverified email address
helpers.logout()
helpers.login(secondary_email_id, PASSWORD)

if 'allow_unverified' in sst_config.flags:
    # Should be able to login with unverified email address
    wait_for(assert_element, **edit_account_anchor)
    helpers.logout()
else:
    # We should NOT be able to login with an unverified email address
    fails(assert_element, **edit_account_anchor)

# Now validate the second email and verify that we can login with it.
helpers.login(primary_email_id, PASSWORD)
helpers.try_to_validate_email(secondary_email_id, vcode)

helpers.logout()
helpers.login(secondary_email_id, PASSWORD)
wait_for(assert_element, **edit_account_anchor)
