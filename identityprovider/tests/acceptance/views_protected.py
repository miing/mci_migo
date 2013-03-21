from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls
from identityprovider.tests.acceptance.shared.devices import (
    add_device,
    authenticate,
)


config.set_base_url_from_env()

# Create account or login to test account
helpers.login_or_register_account(device_cleanup=True)
# Add an authentication device
add_device('views_protected')
helpers.logout_and_in()

# Change the preference to always require 2 factor authentication and save
helpers.set_twofactor_to_always_required()
helpers.logout()

# list of protected urls
helpers.check_2f_for_url(urls.EDIT)
helpers.check_2f_for_url(urls.EMAILS)
helpers.check_2f_for_url(urls.HOME)
helpers.check_2f_for_url(urls.APPLICATIONS)
helpers.check_2f_for_url(urls.NEW_EMAIL)
helpers.check_2f_for_url(urls.VERIFY_EMAIL)
helpers.check_2f_for_url(urls.REMOVE_EMAIL)
# uncomment the following after we have a fully functional saml implementation
#helpers.check_2f_for_url('/+saml')
#helpers.check_2f_for_url('/+saml/process')


helpers.login()
# 2 factor login

authenticate('views_protected')
