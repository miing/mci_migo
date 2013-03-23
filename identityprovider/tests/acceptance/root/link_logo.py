# 3) Check the following links on the login page to ensure they are all
# working:
# Login support, Find out more, Source code for this service, AGPL, Terms of
# Service, Privacy Policy, ubuntu logo {ubuntu.com}

# This tests only the Ubuntu logo.

from sst.actions import (
    assert_title,
    get_element,
    go_to,
    wait_for,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import urls

config.set_base_url_from_env()

go_to(urls.HOME)
wait_for(assert_title, 'Log in')
el = get_element(id='footer-logo')
link = el.find_element_by_tag_name('a')
link.click()
wait_for(assert_title, 'Home | Ubuntu')
