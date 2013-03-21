# 5) Authenticate to a number of 3rd party sites and check the list of
# 'Sites last authenticated to', ensure it is accurate
# 6) Verify that the links in the wlist of 3rd party sites all correcty go to
# the right location
from sst.actions import (
    assert_url_contains,
    click_button,
    click_link,
    get_base_url,
    get_element,
    get_element_by_css,
    get_elements_by_css,
    get_link_url,
    go_to,
    set_wait_timeout,
    wait_for,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls


# Interacting with external sites can take a long time
set_wait_timeout(20)

config.set_base_url_from_env()
helpers.skip_unless_staging_or_production()
helpers.login_to_test_account()

go_to("https://bitbucket.org/account/signin/")
click_link(get_element(text="OpenID log in"))


def openid_link_is_visible():
    return get_element(href="#openid", title="OpenID").is_displayed()
wait_for(openid_link_is_visible)

click_link(get_element(href="#openid", title="OpenID"))
wait_for(lambda: get_element(tag='input', id='openid-url').is_displayed())

input = get_element(tag='input', id='openid-url')
input.clear()
input.send_keys(get_base_url())
submit_button = get_element_by_css(
    'div.buttons.selected button[type=submit]')
click_button(submit_button)

wait_for(get_element, type='submit', name='yes', css_class='btn')
click_button(get_element(type='submit', name='yes', css_class='btn'))

wait_for(assert_url_contains, 'bitbucket.org')

go_to(urls.HOME)
link = get_elements_by_css('#visited-sites tbody td a')[0]

assert get_link_url(link) == "https://bitbucket.org/"
