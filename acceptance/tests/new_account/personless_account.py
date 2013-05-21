# 6) [/new_account 5)] - Create a new account but do not use
# this account to Login to Launchpad, you now have a personless account.
# On Staging request private teams with a personless account and checks a
# private LP resource
# On Production go to the following sites with the personless account:
#  - http://shop.canonical.com
#  - http://wiki.canonical.com
#  - http://pastebin.canonical.com
#  - Also checks a private LP resource
# The wiki & pastebin sites shouldn't allow access to the personless account.
# Shop should allow login.

from sst.actions import (
    assert_element,
    assert_text_contains,
    assert_title,
    click_button,
    click_link,
    end_test,
    get_base_url,
    get_element,
    go_to,
    set_wait_timeout,
    toggle_checkbox,
    write_textfield,
    wait_for,
)
from u1testutils import mail
from u1testutils.sst import config

from acceptance import helpers, urls


config.set_base_url_from_env()

# Some external sites have extraordinary wait times
set_wait_timeout(20)

email_address = mail.make_unique_test_email_address()
account_password = 'Admin007'

go_to(urls.NEW_ACCOUNT)
assert_title('Create account')
helpers.register_account(email_address, password=account_password)

wait_for(assert_element, **{'data-qa-id': 'edit_account'})

# Depending whether we're on Production or Staging different tests
if get_base_url() == 'https://login.ubuntu.com':   # Production
    # shop
    go_to('http://shop.canonical.com')
    wait_for(assert_title, 'Canonical Store')
    click_link(get_element(href="https://shop.canonical.com/login.php"))
    wait_for(get_element, id='id_email')
    write_textfield('id_email', email_address)
    write_textfield('id_password', account_password)
    click_button(get_element(name='continue'))
    click_button(get_element(name='yes'))
    wait_for(get_element, name='email_address')
    assert_element(value=email_address)

    # launchpad
    go_to('https://launchpad.net/~canonical-isd-hackers/+archive/internal-qa/'
          '+index')
    click_button(get_element(name='yes'))
    assert_element(tag='h1', text='Not allowed here')

    # wiki
    go_to('http://wiki.canonical.com')
    click_link(get_element(id="login"))
    go_to('https://wiki.canonical.com/CDO/ISD/Developers/StandupNotes')
    assert_element(tag='strong', text='You are not allowed to view this page.')

    # pastebin
    go_to('https://pastebin.canonical.com/')
    assert_element(tag='h2', text='To continue use 2 factor authentication')
    end_test()

# Staging and local
# XXX: skip if staging until the test can be made to reliably pass
if helpers.is_staging():
    helpers.skip()

# first use test consumer to request private teams, then go to staging LP
go_to(urls.CONSUMER)
wait_for(assert_title, 'Django OpenID Example Consumer')
toggle_checkbox('id_teams')
write_textfield('id_request_teams',
                'canonical-isd-hackers,canonical-isd,canonical')

click_button(get_element(value='Begin'))
wait_for(get_element, name='yes')
click_button(get_element(name='yes'))

wait_for(assert_title, 'Django OpenID Example Consumer')
assert_text_contains(get_element(tag='div', css_class='message success'),
                     'OpenID authentication succeeded')
assert_text_contains(get_element(tag='div', css_class='message answer'),
                     'no teams data')

helpers.skip_unless_staging_or_production()
# staging launchpad, can't run this part locally
go_to('https://staging.launchpad.net/~canonical-isd-hackers/+archive/'
      'internal-qa/+index')
wait_for(get_element, id='id_email')
write_textfield('id_email', email_address)
write_textfield('id_password', account_password)
click_button(get_element(name='continue'))
wait_for(get_element, name='yes')
click_button(get_element(name='yes'))
assert_element(tag='h1', text='Not allowed here')
