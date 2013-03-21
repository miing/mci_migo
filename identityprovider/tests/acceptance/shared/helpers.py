import re
from urllib import quote

from django.conf import settings
from sst.actions import (
    assert_checkbox_value,
    assert_text_contains,
    assert_title,
    assert_title_contains,
    assert_url,
    click_button,
    click_link,
    exists_element,
    get_base_url,
    get_current_url,
    get_element,
    get_element_by_css,
    go_to,
    set_radio_value,
    skip,
    wait_for,
    write_textfield,
)
from sst import config

from u1testutils import mail
from u1testutils.sst.sso.utils import mail as sso_mail

from identityprovider.tests.acceptance.shared import devices, urls


def fail(msg):
    raise AssertionError(msg)


_LAST_EMAIL = None
_LAST_PASSWORD = None


def register_account(email_address=None, displayname="My Name",
                     password="Admin007", fetch_email=True, verify=None):
    """Register an account and verify the token by default.
    If `register_account` creates the email address for you then it returns
    the email address.

    If you pass in an `email_address` then the verification token is returned.
    """
    global _LAST_EMAIL, _LAST_PASSWORD

    if email_address is None:
        email_address = mail.make_unique_test_email_address()

    vcode = None
    go_to(urls.NEW_ACCOUNT)
    wait_for(assert_title, 'Create account')
    fill_registration_form(email_address, displayname, password)
    click_button(get_element(name='continue'))

    vcode = None
    if 'allow_unverified' in config.flags:
        wait_for(assert_title_contains, "%s's details" % displayname)
        # default is not to verify for ALLOW_UNVERIFIED
        if verify is None:
            verify = False
        if verify:
            vlink = sso_mail.get_verification_link_for_address(email_address)
            go_to(vlink)
            click_button(get_element(css_class='btn'))
    else:
        wait_for(assert_title_contains, 'Account creation mail sent')
        # old flow requries verify, usually
        if verify is None:
            verify = True
        if verify:
            vcode = sso_mail.get_verification_code_for_address(email_address)
            write_textfield(get_element(name='confirmation_code'), vcode)
            click_button(get_element(css_class='btn'))

    _LAST_EMAIL = email_address
    _LAST_PASSWORD = password

    return email_address


def fill_registration_form(
        email,
        displayname="My Name",
        password="Admin007",
        passwordconf=None):

    if passwordconf is None:
        passwordconf = password
    write_textfield('id_displayname', displayname)
    write_textfield('id_email', email)
    write_textfield('id_password', password)
    write_textfield('id_passwordconfirm', passwordconf)
    if exists_element(id='recaptcha_response_field'):
        write_textfield('recaptcha_response_field', 'ignored')


def add_email(address, verify=False):
    go_to(urls.EMAILS)
    wait_for(assert_title_contains, "'s email addresses")
    write_textfield('id_newemail', address)
    click_button(get_element(name='continue'))
    code = sso_mail.get_verification_code_for_address(address)
    if verify:
        go_to(urls.ENTER_TOKEN)
        wait_for(write_textfield, 'id_confirmation_code', code)
        write_textfield('id_email', address)
        click_button(get_element(name='continue'))
        assert_title('Complete email address validation')
        click_button(get_element(name='continue'))
    return code


def skip_unless_staging_or_production():
    """Skip a test if not running against staging or production."""
    if not (is_staging() or is_production()):
        print "This test can only be run against staging or production."
        skip()


def skip_production():
    if is_production():
        print 'This test should not run against production.'
        skip()


def production_only():
    if not is_production():
        print 'This is a test only for Production.'
        skip()


def is_devel():
    return not (is_staging() or is_production())


def is_staging():
    url = get_base_url().rstrip('/')
    return url in [
        'https://login.staging.ubuntu.com',
        'https://login.staging.launchpad.net',
    ]


def is_production():
    url = get_base_url().rstrip('/')
    return url in [
        'https://login.ubuntu.com',
        'https://login.launchpad.net',
    ]


def delete_email():
    go_to(urls.EMAILS)
    remove_link = get_element(tag='a', text='Delete')
    click_link(remove_link)
    confirm_button = get_element(name='delete')
    click_button(confirm_button)


def try_to_validate_email(address, code, finish_validation=True):
    go_to(urls.ENTER_TOKEN)
    wait_for(write_textfield, 'id_confirmation_code', code)
    write_textfield('id_email', address)
    click_button(get_element(name='continue'))
    if finish_validation:
        assert_title('Complete email address validation')
        click_button(get_element(name='continue'))


def login_or_register_account(device_cleanup=False):
    # if developer instance, create an account and log in
    if is_devel():
        email = register_account()
    # else use the sanctified QA Account
    else:
        login_to_isdqa_account()
        email = settings.QA_ACCOUNT_EMAIL
        # We only need to cleanup the QA account
        if device_cleanup:
            devices.add_device_cleanup()

    return email


def login(email=None, password=None):
    if email is None and password is None:
        email = _LAST_EMAIL
        password = _LAST_PASSWORD
    go_to(urls.HOME)
    write_textfield('id_email', email)
    write_textfield('id_password', password)
    click_button(get_element(name='continue'))


def logout_and_in():
    """Log out and then back in again, using the email and password from the
    last registered account. Returns to the initial url after login."""
    url = get_current_url()
    logout()
    login(_LAST_EMAIL, _LAST_PASSWORD)
    go_to(url)


def logout():
    go_to(urls.LOGOUT)


def request_password_reset(email_address):
    logout()
    go_to(urls.FORGOT_PASSWORD)
    write_textfield('id_email', email_address)
    # Even though the recaptcha field is ignored for our tests, we do
    # want to verify that it is on the page.
    write_textfield('recaptcha_response_field', 'ignored')
    click_button(get_element(name='continue'))


def login_to_test_account():
    from sst import actions

    login(settings.TEST_ACCOUNT_EMAIL, settings.TEST_ACCOUNT_PASSWORD)
    # Wait for the reload
    wait_for(exists_element, id='ubuntu-header')

    if exists_element(tag='span', css_class='error',
                      text="Password didn't match."):
        if is_production():
            actions._raise("This test requires a test account to be present")

        register_account(settings.TEST_ACCOUNT_EMAIL, "Test Account",
                         settings.TEST_ACCOUNT_PASSWORD)


def login_to_isdqa_account():
    from sst import actions

    global _LAST_EMAIL, _LAST_PASSWORD

    login(settings.QA_ACCOUNT_EMAIL, settings.QA_ACCOUNT_PASSWORD)
    # Wait for the reload
    wait_for(exists_element, id='ubuntu-header')

    if exists_element(tag='span', css_class='error',
                      text="Password didn't match."):
        actions._raise("This test requires a test account to be present")

    _LAST_EMAIL = settings.QA_ACCOUNT_EMAIL
    _LAST_PASSWORD = settings.QA_ACCOUNT_PASSWORD


def login_from_redirect(email=settings.QA_ACCOUNT_EMAIL,
                        password=settings.QA_ACCOUNT_PASSWORD):
    wait_for(assert_title, 'Log in')
    write_textfield('id_email', email)
    write_textfield('id_password', password)
    click_button(get_element(name='continue'))
    wait_for(assert_title_contains, 'Authenticate to')
    click_button(get_element(name='yes'))


def check_2f_for_url(url):
    # are we redirected?
    go_to(url)
    wait_for(assert_title, 'Log in')
    login()
    go_to(url)
    # should be redirected
    assert_url('/two_factor_auth?next=%s' % quote(url))
    logout()


def get_warn_about_backup_device_checkbox():
    return get_element(tag='input', type='checkbox',
                       name='warn_about_backup_device')


def get_backup_device_warning_div():
    return get_element_by_css('#missing_backup_device')


def get_update_preferences_button():
    return get_element(name="update", css_class="btn")


def _set_twofactor(required):
    go_to(urls.EDIT)
    set_radio_value(get_element(tag="input", name="twofactor_required",
                                value=required))
    click_button(get_update_preferences_button())


def set_twofactor_to_always_required():
    _set_twofactor(required=True)


def set_twofactor_to_required_as_needed():
    _set_twofactor(required=False)


def assert_backup_device_warning():
    go_to(urls.EDIT)
    assert_checkbox_value(get_warn_about_backup_device_checkbox(), True)
    warning = get_backup_device_warning_div()
    # ensure a single message is shown
    messages = warning.find_elements_by_tag_name('p')
    assert len(messages) == 1
    assert_text_contains(
        messages[0], 'We strongly recommend having two authentication devices')
    assert_text_contains(
        messages[0], 'Click to add a backup device.')


def get_password_reset_link(email_address):
    msg = mail.get_latest_email_sent_to(email_address).as_string()
    reset_link_re = (
        r'(http(?:s)?://[a-zA-Z_\-\.]*(?::[0-9]+)?/'
        r'token/(?:.*)/\+resetpassword/.*)'
    )
    this_line = ''
    for line in msg.splitlines():
        if line.endswith('='):
            this_line += line[:-1]
            continue

        this_line += line
        match = re.match(reset_link_re, this_line)
        if match:
            break
        this_line = ''
    else:
        raise AssertionError('Password reset link not found')

    link = match.groups()[0]
    return link
