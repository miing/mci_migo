# Copyright 2013 Canonical Ltd.
# This software is licensed under the GNU Affero General Public License
# version 3 (see the file LICENSE).

import logging

import sst.actions
import u1testutils.sso.sst.pages

from u1testutils.sst import log_action


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
        remove_link = sst.actions.get_element(tag='a', text='Delete')
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
