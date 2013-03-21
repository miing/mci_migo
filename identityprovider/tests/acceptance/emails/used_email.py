from sst.actions import (
    fails,
)
from u1testutils import mail
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers


config.set_base_url_from_env()

primary_email_id = mail.make_unique_test_email_address()
secondary_email_id = mail.make_unique_test_email_address()

# Create and verify account A
helpers.register_account(primary_email_id)

# Add and verify 2nd email
vcode = helpers.add_email(secondary_email_id)
helpers.try_to_validate_email(secondary_email_id, vcode)

# Logout
helpers.logout()

# Ensure that creating a new account using that 2nd email fails.
fails(helpers.register_account, secondary_email_id, verify=False)
