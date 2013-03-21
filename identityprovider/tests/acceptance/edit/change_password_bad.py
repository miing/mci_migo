#  password tests: client-side validation of update password
#
#  rules:
#    Password must be at least 8 characters long.

from django.conf import settings
from sst.actions import (
    assert_element,
    click_button,
    get_element,
    write_textfield,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers


# Set to Production, Staging, VPS, Developer etc..
config.set_base_url_from_env()

# Login so that we can attempt to change the password
helpers.login(settings.QA_ACCOUNT_EMAIL, settings.QA_ACCOUNT_PASSWORD)

# Write the new password into the fields
write_textfield('id_password', new_password)
write_textfield('id_passwordconfirm', new_password)

# Attempt to submit the new passwords, but the password is bad
click_button(get_element(name="update"))
expected = 'Password must be at least 8 characters long.'
assert_element(text=expected)
