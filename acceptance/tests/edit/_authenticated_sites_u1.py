# NOTE:
# This test can only be run on SSO production
#
#
# 5) Authenticate to a number of 3rd party sites and check the list of
# 'Sites last authenticated to', ensure it is accurate
# 6) Verify that the links in the wlist of 3rd party sites all correcty go to
# the right location
from sst.actions import (
    assert_title,
    browser,
    click_button,
    get_element,
    get_elements_by_css,
    get_link_url,
    go_to,
)
from u1testutils.sst import config

from acceptance import helpers, urls


config.set_base_url_from_env(default_to='https://login.ubuntu.com/')

helpers.production_only()

helpers.login_to_test_account()

go_to("https://one.ubuntu.com/services/plan/subscribe_basic/")
if 'Confirm Subscription' in browser.title:
    click_button(get_element(type='submit', name='subscribe'))

assert_title("Ubuntu One : Dashboard")

go_to(urls.HOME)

link = get_elements_by_css('#visited-sites tbody td a')[0]

assert get_link_url(link) == "https://one.ubuntu.com/"
