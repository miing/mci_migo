# Copyright 2013 Canonical Ltd.
# This software is licensed under the GNU Affero General Public License
# version 3 (see the file LICENSE).

import logging

import sst.actions
import u1testutils.sso.sst.pages

from base64 import b32decode
from urlparse import urlparse, parse_qs

from u1testutils.sst import log_action


class PageWithUserSubheader(u1testutils.sst.Page):

    def __init__(self, open_page=False):
        self.subheader = UserSubheader()
        super(PageWithUserSubheader, self).__init__(open_page)


class UserSubheader(u1testutils.sso.sst.pages.UserSubheader):
    """The subheader of all the SSO pages.

    Extends the class in u1testutils with all the actions that are only needed
    by SSO tests.

    """

    @log_action(logging.info)
    def go_to_authentication_devices(self):
        sst.actions.click_link('devices-link')
        return YourAuthenticationDevices()


class PageWithUsernameInTitle(PageWithUserSubheader):

    def assert_title(self):
        user_name = self.subheader.get_user_name()
        title = self.title.format(user_name)
        sst.actions.assert_title(title)


class LogIn(u1testutils.sso.sst.pages.LogIn):
    """Log in page of the Ubuntu Single Sign On website.

    Extends the class in u1testutils to return the Your Account page  with all
    the actions available.

    """

    @log_action(logging.info)
    def log_in_to_site_recognized(self, user=None):
        """Fill the log in form and continue to the site that requested it.

        Keyword arguments:
        user -- The user credentials. It must have the attributes email and
            password. If None is passed as the user, it means that the user
            has already started session on the identity provider and it's not
            necessary to enter the credentials again.

        """
        self._log_in(user)
        return YourAccount(user.full_name)


class YourAccount(PageWithUserSubheader):
    """Your account page of the Ubuntu Single Sign On website.

    Extends the class in u1testutils to use the subheader with all the actions
    available.

    """

    title = "{0}'s details"
    url_path = '/'
    qa_anchor = 'edit_account'

    def __init__(self, user_name, open_page=False):
        self.title = self.title.format(user_name)
        super(YourAccount, self).__init__(open_page)


class YourEmailAddresses(u1testutils.sso.sst.pages.PageWithUserSubheader):

    title = "{0}'s email addresses"
    url_path = '/+emails'
    qa_anchor = 'account_emails'

    def assert_title(self):
        user_name = self.subheader.get_user_name()
        sst.actions.assert_title(self.title.format(user_name))

    @log_action(logging.info)
    def add_email(self, email_address):
        sst.actions.write_textfield('id_newemail', email_address)
        sst.actions.click_button(sst.actions.get_element(name='continue'))

    @log_action(logging.info)
    def delete_email(self):
        remove_link = sst.actions.get_element_by_css(
            '*[data-qa-id="remove_verified_email"]')
        sst.actions.click_link(remove_link)
        return DeleteEmail()


class EnterConfirmationCode(u1testutils.sso.sst.pages.PageWithUserSubheader):

    title = 'Enter confirmation code'
    url_path = '/+enter_token'

    @log_action(logging.info)
    def confirm(self, confirmation_code, email_address):
        self._fill_confirmation_form(confirmation_code, email_address)
        self._continue()
        return u1testutils.sso.sst.pages.CompleteEmailValidation()

    def _fill_confirmation_form(self, confirmation_code, email_address):
        sst.actions.write_textfield('id_confirmation_code', confirmation_code)
        sst.actions.write_textfield('id_email', email_address)

    def _continue(self):
        sst.actions.click_button(sst.actions.get_element(name='continue'))

    @log_action(logging.info)
    def confirm_with_error(self, confirmation_code, email_address):
        self._fill_confirmation_form(confirmation_code, email_address)
        self._continue()
        return self


class DeleteEmail(u1testutils.sso.sst.pages.PageWithUserSubheader):

    title = 'Delete unverified email'
    url_path = '/+remove-email'

    @log_action(logging.info)
    def confirm(self):
        confirm_button = sst.actions.get_element(name='delete')
        sst.actions.click_button(confirm_button)
        user_name = self.subheader.get_user_name()
        return YourEmailAddresses(user_name)


class ResetPassword(u1testutils.sso.sst.pages.PageWithAnonymousSubheader):

    title = 'Reset password'
    url_path = '/+forgot_password'
    headings1 = [
        'Ubuntu Single Sign On',
        'Reset your Ubuntu Single Sign On password'
    ]
    qa_anchor = 'forgot_password_step_1'

    @log_action(logging.info)
    def request_password_reset(self, email_address):
        sst.actions.write_textfield('id_email', email_address)
        # Even though the recaptcha field is ignored for our tests, we do
        # want to verify that it is on the page.
        sst.actions.write_textfield('recaptcha_response_field', 'ignored')
        sst.actions.click_button(sst.actions.get_element(name='continue'))


class LogInFromRedirect(u1testutils.sso.sst.pages.LogIn):

    url_path = '/.*/\+decide'
    is_url_path_regex = True
    headings2 = ['Log in', 'Are you new?']


# Devices pages.

class YourAuthenticationDevices(PageWithUsernameInTitle):

    title = "{0}'s devices"
    url_path = '/device-list'
    headings1 = ['Ubuntu Single Sign On', 'Your authentication devices']
    qa_anchor = 'device_list'

    def get_devices(self):
        """Get a list with the name of the devices added by the user."""
        if sst.actions.exists_element(id='device-list'):
            get_text = lambda x: x.text
            return map(
                get_text, sst.actions.get_elements_by_css(
                    '#device-list td.name'))
        else:
            return []

    @log_action(logging.info)
    def add_new_authentication_device(self):
        add_link = sst.actions.get_element_by_css(
            '*[data-qa-id="add_new_device"]'
        )
        sst.actions.click_link(add_link)
        return AddNewAuthenticationDevice()

    @log_action(logging.info)
    def delete_authentication_device(self, index=0):
        delete_link = sst.actions.get_elements_by_css(
            '*[data-qa-id="delete_device"]')
        sst.actions.click_link(delete_link[index])
        return DeleteAuthenticationDevice()

    def is_warning_displayed(self):
        try:
            warning_message = sst.actions.get_element_by_css(
                '#missing_backup_device')
            return warning_message.is_displayed()
        except AssertionError:
            return False


class DeleteAuthenticationDevice(PageWithUsernameInTitle):

    title = "{0}'s devices"
    url_path = '/device-removal/.*'
    is_url_path_regex = True
    headings1 = ['Ubuntu Single Sign On', 'Delete device?']
    qa_anchor = 'device_removal'

    @log_action(logging.info)
    def cancel(self):
        cancel_link = sst.actions.get_element_by_css(
            '*[data-qa-id="cancel_deleting_this_device"]'
        )
        sst.actions.click_link(cancel_link)
        return YourAuthenticationDevices()

    @log_action(logging.info)
    def confirm_delete_device(self):
        delete_anchor = sst.actions.get_element_by_css(
            '*[data-qa-id="delete_this_device"]')
        sst.actions.click_element(delete_anchor)
        return YourAuthenticationDevices()


class AddNewAuthenticationDevice(PageWithUsernameInTitle):

    title = "{0}'s devices"
    url_path = '/device-addition'
    headings1 = ['Ubuntu Single Sign On', 'Add a new authentication device']
    qa_anchor = 'device_addition'

    @log_action(logging.info)
    def cancel(self):
        cancel_link = sst.actions.get_element_by_css('*[data-qa-id="cancel"]')
        sst.actions.click_link(cancel_link)
        return YourAuthenticationDevices()

    @log_action(logging.info)
    def get_selected_device(self):
        identifiers = ['type_google', 'type_yubi', 'type_generic']
        if 'paper_device' in sst.config.flags:
            identifiers.append('type_paper')
        for identifier in identifiers:
            radio = sst.actions.get_element(id=identifier)
            if radio.is_selected():
                return identifier

    def is_paper_device_displayed(self):
        try:
            paper_device_radio = sst.actions.get_element(id='type_paper')
            return paper_device_radio.is_displayed()
        except AssertionError:
            return False

    @log_action(logging.info)
    def add_generic_device(self):
        self._add_device('type_generic')
        return AddGenericDevice()

    @log_action(logging.info)
    def add_google_device(self):
        self._add_device('type_google')
        return AddGoogleDevice()

    @log_action(logging.info)
    def add_yubikey_device(self):
        self._add_device('type_yubi')
        return AddYubikeyDevice()

    @log_action(logging.info)
    def add_paper_device(self):
        self._add_device('type_paper')
        return PaperDevice()

    def _add_device(self, device_radio_identifier):
        sst.actions.set_radio_value(device_radio_identifier)
        add_button = sst.actions.get_element(
            tag='button', text_regex='Add device')
        sst.actions.click_button(add_button)


class AddDevice(PageWithUsernameInTitle):

    title = "{0}'s devices"
    url_path = '/device-addition'
    headings1 = ['Ubuntu Single Sign On', 'Add device']
    qa_anchor = 'device_addition'

    @log_action(logging.info)
    def add_device(self, name, one_time_password):
        self._fill_device_form(name, one_time_password)
        self._click_add_device()
        return YourAuthenticationDevices()

    def _fill_device_form(self, name, one_time_password):
        if name is not None:
            sst.actions.write_textfield(self._get_name_text_field(), name)
        if one_time_password is not None:
            sst.actions.write_textfield(
                self._get_one_time_password_text_field(), one_time_password)

    def _click_add_device(self):
        add_button = sst.actions.get_element_by_css(
            '*[data-qa-id="add_generic_device"]')
        sst.actions.click_button(add_button)

    @log_action(logging.info)
    def add_device_with_errors(self, name, one_time_password):
        self._fill_device_form(name, one_time_password)
        self._click_add_device()
        return self

    def _get_name_text_field(self):
        return sst.actions.get_element(tag='input', name='name')

    def _get_one_time_password_text_field(self):
        return sst.actions.get_element(tag='input', name='otp')

    def get_form_values(self):
        name = self._get_name_text_field().get_attribute('value')
        one_time_password_text_field = self._get_one_time_password_text_field()
        one_time_password = one_time_password_text_field.get_attribute('value')
        return name, one_time_password

    def get_form_errors(self):
        try:
            name_error = sst.actions.get_element(id='name-error').text
        except AssertionError:
            name_error = None
        try:
            one_time_password_error = sst.actions.get_element(
                id='otp-error').text
        except AssertionError:
            one_time_password_error = None
        return name_error, one_time_password_error

    @log_action(logging.info)
    def cancel(self):
        cancel_link = sst.actions.get_element_by_css('*[data-qa-id="cancel"]')
        sst.actions.click_link(cancel_link)
        return YourAuthenticationDevices()


class AddGenericDevice(AddDevice):

    qa_anchor = 'generic_device_addition'

    def get_key(self):
        return sst.actions.get_element(name='hex_key').get_attribute('value')


class AddGoogleDevice(AddDevice):

    def get_key(self, email):
        return self._get_key_from_qrcode(email)

    def _get_key_from_qrcode(self, email):
        img = sst.actions.get_element(tag='img', css_class='qrcode')
        src = img.get_attribute('src')
        # check the url is well formed
        url = urlparse(src)
        assert url.scheme == 'https', "incorrect google charts protocol"
        msg = "incorrect google charts domain"
        assert url.netloc == 'chart.googleapis.com', msg
        qs = parse_qs(url.query)['chl'][0]
        otpauth = urlparse(qs)
        assert email in otpauth.path
        # python2.7.3 on quantal has a backport from 2.7 trunk (presumably
        # will be 2.7.4) and now urlparse correctly handles query string on
        # *all* url types
        if otpauth.query:
            # urlparse has handled query string
            query = otpauth.query
        else:
            # we need to handle query string parsing
            query = otpauth.path.split('?')[1]
        b32_key = parse_qs(query)['secret'][0]
        aes_key = b32decode(b32_key).encode('hex')
        return aes_key


class AddYubikeyDevice(AddDevice):

    def get_key(self):
        return sst.actions.get_element(name='hex_key').get_attribute('value')

    # TODO make a new test_open_add_yubikey_page on the yubikey page object,
    # add two functions: is_warning_displayed and get_warning_message
    # and assert both of them on the new test. This test is really small and
    # gives no real value to a user, so it's a perfect candidate to be
    # converted into a django unit test.
    def assert_warning(self):
        # Check that the YubiKey warning is showing
        warning = ('Warning: The YubiKey is shipped with a credential in the '
                   'short-press slot')
        sst.actions.assert_element(css_class='warning', text_regex=warning)


class PaperDevice(PageWithUsernameInTitle):

    title = "{0}'s devices"
    url_path = '/device-print/.*'
    is_url_path_regex = True
    headings1 = ['Ubuntu Single Sign On', 'Printable backup codes']

    # TODO This test is really small and gives no real value to a user, so it's
    # a perfect candidate to be converted into a django unit test.
    def assert_codes_present(self):
        # codelist has list of N codes
        sst.actions.assert_element('*[data-qa-id="codelist"]')

    # TODO This test is really small and gives no real value to a user, so it's
    # a perfect candidate to be converted into a django unit test.
    def assert_print_button_visible(self):
        sst.actions.assert_element('*[data-qa-id="print_btn"]')

    @log_action(logging.info)
    def go_back_to_device_list(self):
        device_list_link = sst.actions.get_element_by_css(
            '*[data-qa-id="go_back"]')
        sst.actions.click_link(device_list_link)
        return YourAuthenticationDevices()

    @log_action(logging.info)
    def generate_new_codes(self):
        generate_link = sst.actions.get_element_by_css(
            '*[data-qa-id="generate_codes"]')
        sst.actions.click_link(generate_link)
        return GenerateNewPaperCodes()

    def get_first_code(self):
        return sst.actions.get_elements_by_css(
            '*[data-qa-id="codelist"]')[0].text

    # TODO migrate the paper device functions below
    #def store_paper_device(self, name='Printable Backup Codes'):
    #    acceptance.devices.store_paper_device(name)

    #def update_paper_device(self, name='Printable Backup Codes'):
    #    acceptance.devices.update_paper_device(name)


class GenerateNewPaperCodes(PageWithUsernameInTitle):

    title = "{0}'s devices"
    url_path = '/device-generate/.*'
    is_url_path_regex = True
    headings1 = ['Ubuntu Single Sign On', 'Generate new codes']

    @log_action(logging.info)
    def confirm_new_codes(self):
        confirm_button = sst.actions.get_element_by_css(
            '*[data-qa-id="confirm-codes"]')
        sst.actions.click_button(confirm_button)
        return PaperDevice()

    @log_action(logging.info)
    def cancel(self):
        cancel_link = sst.actions.get_element_by_css('*[data-qa-id="cancel"]')
        sst.actions.click_link(cancel_link)
        return PaperDevice()
