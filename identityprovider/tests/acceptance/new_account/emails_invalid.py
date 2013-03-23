# validation of emails

from django.conf import settings
from sst.actions import (
    assert_element,
    click_button,
    get_element,
    go_to,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls


# Set to Production, Staging, VPS, Developer etc..
config.set_base_url_from_env()

# Attempt to create a new account using invalid emails
go_to(urls.NEW_ACCOUNT)
helpers.fill_registration_form(
    invalid_email,
    displayname='test name',
    password=settings.QA_ACCOUNT_PASSWORD
)
click_button(get_element(name="continue"))
assert_element(text='Invalid email.')
