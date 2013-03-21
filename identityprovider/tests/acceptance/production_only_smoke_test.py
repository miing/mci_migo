# 1) Ensure that the following consumers are all allowing OpenID login with
# SSO:
# ubuntuone.com, Payments - note that pastebin, canonical wiki, launchpad
# etc are all
# automated in new_accountpersonless_account.py that will be run as soon as
# Production goes live


from django.conf import settings
from sst.actions import (
    assert_element,
    assert_title,
    click_button,
    click_link,
    get_element,
    go_to,
    set_wait_timeout,
    write_textfield,
    wait_for,
)
from u1testutils.sst import config

from helpers import logout, production_only

config.set_base_url_from_env()

# Some external sites have extraordinary wait times
set_wait_timeout(20)

# Check whether we're on Production or not
production_only()

# Ubuntu One
go_to('http://ubuntuone.com')
click_link(get_element(text="Log in or Sign up"))
write_textfield('id_email', settings.QA_ACCOUNT_EMAIL)
write_textfield('id_password', settings.QA_ACCOUNT_PASSWORD)
click_button(get_element(name='continue'))
assert_element(tag='span', text='Welcome ISD Test')
logout()

# Payment system
go_to('https://pay.ubuntu.com/')
click_link(get_element(text="Log in or Register"))
wait_for(assert_title, 'Log in')
write_textfield('id_email', settings.QA_ACCOUNT_EMAIL)
write_textfield('id_password', settings.QA_ACCOUNT_PASSWORD)
click_button(get_element(name='continue'))
assert_element(tag='h1', text='Your payment history')
logout()
