# Copyright 2013 Canonical Ltd.
# This software is licensed under the GNU Affero General Public License
# version 3 (see the file LICENSE).

import logging

import sst.actions
import u1testutils.sso.sst.pages

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

    def __init__(self, user_name, open_page=False):
        self.title = self.title.format(user_name)
        super(YourAccount, self).__init__(open_page)


class YourEmailAddresses(u1testutils.sso.sst.pages.PageWithUserSubheader):

    title = "{0}'s email addresses"
    url_path = '/+emails'

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
            'a[data-qa-id="remove-email"]')
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
        add_link = sst.actions.get_element_by_css('a[data-qa-id="add-device"]')
        sst.actions.click_link(add_link)
        return AddNewAuthenticationDevice()


class AddNewAuthenticationDevice(PageWithUsernameInTitle):

    title = "{0}'s devices"
    url_path = '/device-addition'
    headings1 = ['Ubuntu Single Sign On', 'Add a new authentication device']

    @log_action(logging.info)
    def cancel(self):
        cancel_link = sst.actions.get_element_by_css('a[data-qa-id="cancel"]')
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

    def _add_device(self, device_radio_identifier):
        sst.actions.set_radio_value(device_radio_identifier)
        add_button = sst.actions.get_element(
            tag='button', text_regex='Add device')
        sst.actions.click_button(add_button)


class AddDevice(PageWithUsernameInTitle):

    title = "{0}'s devices"
    url_path = '/device-addition'
    headings1 = ['Ubuntu Single Sign On', 'Add device']

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
            'button[data-qa-id="add-device"]')
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
        cancel_link = sst.actions.get_element_by_css('a[data-qa-id="cancel"]')
        sst.actions.click_link(cancel_link)
        return YourAuthenticationDevices()


class AddGenericDevice(AddDevice):

    def get_key(self):
        return sst.actions.get_element(name='hex_key').get_attribute('value')
