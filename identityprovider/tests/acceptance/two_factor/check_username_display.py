# Check two factor page displays the username, account and logout options.

from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers

from actions import (
    subheader,
    two_factor,
)


config.set_base_url_from_env()

display_name = "Fred Jones"
# Create an account and login.
helpers.register_account(displayname=display_name)

# Go to two factor auth page
two_factor.open_page()
# check subheader navbar displays user info
subheader.assert_log_in(display_name)
