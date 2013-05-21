# 13) Check missing required fields do not allow submission of the form

from sst.actions import (
    assert_title,
    click_button,
    get_element,
    get_element_by_css,
    go_to,
    wait_for,
    write_textfield,
)
from u1testutils.sst import config

from acceptance import urls


config.set_base_url_from_env()

go_to(urls.HOME)
wait_for(assert_title, 'Log in')

if email:
    print 'Sending e-mail'
    write_textfield('id_email', 'bogus@canonical.com')
if password:
    print 'Sending password'
    write_textfield('id_password', 'bogus')

click_button(get_element_by_css('*[data-qa-id="ubuntu_login_button"]'))
wait_for(assert_title, 'Log in')

el = get_element(id='login-form')
els = el.find_elements_by_class_name('error')
els = [e for e in els if e.text == 'Required field.']

assert len(els) == errors
