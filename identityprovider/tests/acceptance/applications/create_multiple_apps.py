# 2) Using the script attached to this topic, run the command -
# ./create_app_token.sh "Your account email @ your domain.com" "Your Password"
# "<Rollout URL 'no http'>" - then go to the <Rollout URL> and login check the
# applications list and you should now see the test token in the applications
# tab. It is ok if there are duplicates.)

import urllib2

from sst.actions import (
    assert_text_contains,
    get_base_url,
    go_to,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls


PASSWORD = 'Admin007'
TOKEN_1 = 'chupacabra'
TOKEN_2 = 'leviathan'
TOKEN_3 = 'behemoth'

config.set_base_url_from_env()

# Create an account
email_address = helpers.register_account()

# Make sure we are not logged in
helpers.logout()

# Authenticate via the api so that an application can be created
api_urls = [
    ('%s/api/1.0/authentications?ws.op=authenticate&token_name=%s' %
     (get_base_url(), TOKEN_1)),
    ('%s/api/1.0/authentications?ws.op=authenticate&token_name=%s' %
     (get_base_url(), TOKEN_2)),
    ('%s/api/1.0/authentications?ws.op=authenticate&token_name=%s' %
     (get_base_url(), TOKEN_3)),
]
password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
for url in api_urls:
    password_mgr.add_password(None, url, email_address, PASSWORD)
    opener = urllib2.build_opener(urllib2.HTTPBasicAuthHandler(password_mgr))
    urllib2.install_opener(opener)
    req = urllib2.Request(url)
    urllib2.urlopen(req)

# Now log in and check that the apps are associated with the account.
helpers.login(email_address, PASSWORD)
go_to(urls.APPLICATIONS)
assert_text_contains('content', 'chupacabra')
assert_text_contains('content', "leviathan")
assert_text_contains('content', "behemoth")
