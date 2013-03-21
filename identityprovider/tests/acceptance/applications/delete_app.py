#1) Check you are able to delete any app and verify that it does not
# reappear after logout/in

import urllib2

from sst.actions import (
    assert_text_contains,
    click_button,
    fails,
    get_base_url,
    get_element,
    go_to,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls


PASSWORD = 'Admin007'
TOKEN_NAME = 'Whatever'
config.set_base_url_from_env()

# Create an account
email_address = helpers.register_account()

# Make sure we are not logged in
helpers.logout()

# Authenticate via the api so that an application can be created
url = ('%s/api/1.0/authentications?ws.op=authenticate&token_name=%s' %
       (get_base_url(), TOKEN_NAME))
password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
password_mgr.add_password(None, url, email_address, PASSWORD)
opener = urllib2.build_opener(urllib2.HTTPBasicAuthHandler(password_mgr))
urllib2.install_opener(opener)

req = urllib2.Request(url)
f = urllib2.urlopen(req)
data = f.read()

# now test that the app is there and that  we can delete it
helpers.login(email_address, PASSWORD)
go_to(urls.APPLICATIONS)
assert_text_contains('content', TOKEN_NAME)
click_button(get_element(css_class='btn-sm', name='Delete'))
# log back in and should have no app or delete button
helpers.logout()
helpers.login(email_address, PASSWORD)
go_to(urls.APPLICATIONS)
fails(assert_text_contains, 'content', TOKEN_NAME)
fails(get_element, css_class='btn-sm', name='Delete')
