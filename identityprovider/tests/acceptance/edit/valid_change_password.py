#  password tests: change password with valid passwords
#
# rules:
#   Password must be at least 8 characters long.

from django.conf import settings
from sst.actions import (
    assert_element,
    click_button,
    click_link,
    get_element,
    write_textfield,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers


# Set to Production, Staging, VPS, Developer etc..
config.set_base_url_from_env()

# Login so we can change the password
helpers.login(settings.QA_ACCOUNT_EMAIL, settings.QA_ACCOUNT_PASSWORD)

# Change the password on the account and logout
write_textfield('id_password', new_password)
write_textfield('id_passwordconfirm', new_password)
click_button(get_element(name="update"))
assert_element(text='Your account details have been successfully updated')
click_link('logout-link')

# Login with the new password
helpers.login(settings.QA_ACCOUNT_EMAIL, password=new_password)

# Change the password back
write_textfield('id_password', settings.QA_ACCOUNT_PASSWORD)
write_textfield('id_passwordconfirm', settings.QA_ACCOUNT_PASSWORD)
click_button(get_element(name="update"))
assert_element(text='Your account details have been successfully updated')
