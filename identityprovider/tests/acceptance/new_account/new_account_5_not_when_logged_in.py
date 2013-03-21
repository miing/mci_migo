# The token generated when creating a new account should not be able to
# be used with other email addresses.
from sst.actions import (
    assert_title,
    go_to,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls


config.set_base_url_from_env()

email_address_for_token = helpers.register_account(displayname="Fred Stone")

# Now that we're logged in with the new account, we try creating
# another new account...but are redirected back to our details.
go_to(urls.NEW_ACCOUNT)
assert_title("Fred Stone's details")
