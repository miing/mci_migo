# 5) Authenticate to a number of 3rd party sites and check the list of
# 'Sites last authenticated to', ensure it is accurate
# 6) Verify that the links in the wlist of 3rd party sites all correcty go to
# the right location
from sst.actions import (
    assert_title,
    assert_url_contains,
    click_button,
    exists_element,
    get_base_url,
    get_element,
    get_elements_by_css,
    get_link_url,
    go_to,
    set_wait_timeout,
    wait_for,
    write_textfield,
)
from u1testutils.sst import config

from acceptance import helpers, urls


# Interacting with external sites can take a long time
set_wait_timeout(20)

config.set_base_url_from_env()
helpers.skip_unless_staging_or_production()
helpers.login_to_test_account()

go_to("http://askubuntu.com/users/authenticate/")
if exists_element(id='more-options-link'):
    get_element(id='more-options-link').click()

    def openid_input_is_displayed():
        return get_element(id='openid_identifier').is_displayed()

    wait_for(openid_input_is_displayed)

write_textfield('openid_identifier', get_base_url())
click_button('submit-button')

wait_for(get_element, type='submit', name='yes', css_class='btn')
click_button(get_element(type='submit', name='yes', css_class='btn'))

wait_for(assert_url_contains, 'askubuntu.com')
if exists_element(type="submit", value="Confirm and Create New Account"):
    click_button(get_element(type="submit",
                             value="Confirm and Create New Account"))
    wait_for(assert_title, "Ask Ubuntu - Stack Exchange")

go_to(urls.HOME)
link = get_elements_by_css('#visited-sites tbody td a')[0]

assert get_link_url(link) == "http://askubuntu.com/users/authenticate/"
