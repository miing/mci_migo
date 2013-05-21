import re
from urllib import quote

import u1testutils.sso.sst.pages

from django.conf import settings
from sst.actions import (
    assert_checkbox_value,
    assert_text_contains,
    assert_title,
    assert_url,
    click_button,
    exists_element,
    get_base_url,
    get_current_url,
    get_element,
    get_element_by_css,
    go_to,
    set_radio_value,
    skip,
    wait_for,
)
from sst import config
from u1testutils import mail
from u1testutils.sso import (
    data,
    mail as sso_mail
)

from acceptance import devices, pages, urls


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

    create_account = u1testutils.sso.sst.pages.CreateAccount(open_page=True)

    user = data.User(displayname, email_address, password)
    create_account.create_ubuntu_sso_account(user)

    vcode = None
    if 'allow_unverified' in config.flags:
        u1testutils.sso.sst.pages.YourAccount(user.full_name)
        # default is not to verify for ALLOW_UNVERIFIED
        if verify is None:
            verify = False
        if verify:
            vlink = sso_mail.get_verification_link_for_address(email_address)
            go_to(vlink)
            validate_email = \
                u1testutils.sso.sst.pages.CompleteEmailValidation()
            validate_email.confirm()
    else:
        mail_sent = u1testutils.sso.sst.pages.AccountCreationMailSent()
        # old flow requries verify, usually
        if verify is None:
            verify = True
        if verify:
            vcode = sso_mail.get_verification_code_for_address(email_address)
            # TODO add the site not recognized parameter and use the right
            # public method.
            mail_sent._confirm_email(vcode)

    _LAST_EMAIL = email_address
    _LAST_PASSWORD = password

    return email_address


def fill_registration_form(
        email, displayname="My Name", password="Admin007", passwordconf=None):

    user = data.User(displayname, email, password)
    create_account = u1testutils.sso.sst.pages.CreateAccount(open_page=True)
    # TODO we either make the fill public, or call a public higher method,
    # The latter sounds better.
    create_account._fill_new_account_form(user, passwordconf)


def add_email(address, verify=False):
    your_email_addresses = pages.YourEmailAddresses(open_page=True)
    your_email_addresses.add_email(address)
    code = sso_mail.get_verification_code_for_address(address)
    if verify:
        enter_confirmation_code = pages.EnterConfirmationCode(open_page=True)
        complete_email_validation = enter_confirmation_code.confirm(
            code, address)
        complete_email_validation.confirm()
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
    your_email_addresses = pages.YourEmailAddresses(open_page=True)
    delete_email_confirmation = your_email_addresses.delete_email()
    delete_email_confirmation.confirm()


def try_to_validate_email(address, code, finish_validation=True):
    # TODO implement the navigation and use the right public methods.
    enter_confirmation_code = pages.EnterConfirmationCode(open_page=True)
    enter_confirmation_code._fill_confirmation_form(
        code, address)
    enter_confirmation_code._continue()
    if finish_validation:
        complete = u1testutils.sso.sst.pages.CompleteEmailValidation()
        complete.confirm()


def login_or_register_account(device_cleanup=False):
    # if developer instance, create an account and log in
    if is_devel():
        email = register_account()
    # else use the sanctified QA Account
    else:
        login_to_isdqa_account()
        email = settings.SSO_TEST_ACCOUNT_EMAIL
        # We only need to cleanup the QA account
        if device_cleanup:
            devices.add_device_cleanup()

    return email


def login(email=None, password=None):
    if email is None and password is None:
        email = _LAST_EMAIL
        password = _LAST_PASSWORD
    log_in = u1testutils.sso.sst.pages.LogIn(open_page=True)
    # TODO we need the user name too.
    user = data.User('TODO', email, password)
    # TODO add the site not recognized parameter and use the right public
    # method.
    log_in._log_in(user)


def logout_and_in():
    """Log out and then back in again, using the email and password from the
    last registered account. Returns to the initial url after login."""
    url = get_current_url()
    logout()
    login(_LAST_EMAIL, _LAST_PASSWORD)
    go_to(url)


def logout():
    u1testutils.sso.sst.pages.YouHaveBeenLoggedOut(open_page=True)


def request_password_reset(email_address):
    logout()
    reset_password = pages.ResetPassword(open_page=True)
    reset_password.request_password_reset(email_address)


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

    login(settings.SSO_TEST_ACCOUNT_EMAIL, settings.SSO_TEST_ACCOUNT_PASSWORD)
    # Wait for the reload
    wait_for(exists_element, id='ubuntu-header')

    if exists_element(tag='span', css_class='error',
                      text="Password didn't match."):
        actions._raise("This test requires a test account to be present")

    _LAST_EMAIL = settings.SSO_TEST_ACCOUNT_EMAIL
    _LAST_PASSWORD = settings.SSO_TEST_ACCOUNT_PASSWORD


def login_from_redirect(email=settings.SSO_TEST_ACCOUNT_EMAIL,
                        password=settings.SSO_TEST_ACCOUNT_PASSWORD):
    log_in = pages.LogInFromRedirect()
    # TODO we also need the user name.
    user = data.User('TODO', email, password)
    site_not_recognized = log_in.log_in_to_site_not_recognized(user)
    site_not_recognized.make_all_information_available_to_website()
    site_not_recognized.yes_sign_me_in()


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
        r'(http(?:s)?://[a-zA-Z0-9_\-\.]*(?::[0-9]+)?/'
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
