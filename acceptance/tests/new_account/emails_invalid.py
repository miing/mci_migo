# validation of emails
from django.conf import settings

from sst.actions import (
    assert_element,
    click_button,
    get_element,
    go_to,
    skip
)
from u1testutils.sst import config

from acceptance import helpers, urls

from identityprovider.utils import get_current_brand


# the reason why this test is incompatible
# with the u1 brand is because of the
# input email type usage. Firefox will
# prevent user from submitting the form
# if the email is not valid
if get_current_brand() == 'ubuntuone':
    skip('Test not compatible with ubuntuone brand')

# Set to Production, Staging, VPS, Developer etc..
config.set_base_url_from_env()

# Attempt to create a new account using invalid emails
go_to(urls.NEW_ACCOUNT)
helpers.fill_registration_form(
    invalid_email,
    displayname='test name',
    password=settings.SSO_TEST_ACCOUNT_PASSWORD
)
click_button(get_element(name="continue"))
assert_element(text='Invalid email.')
