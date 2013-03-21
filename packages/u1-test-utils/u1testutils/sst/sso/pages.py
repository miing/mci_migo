# -*- coding: utf-8 -*-

# Copyright 2013 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 3, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import sst.actions


class Page(object):
    """Base class for the page objects used in acceptance testing.

    Instance variables:
    title -- The title of the page.

    """

    title = None

    def __init__(self):
        super(Page, self).__init__()
        self.assert_page_is_open()

    def assert_page_is_open(self):
        """Assert that the page is open."""
        sst.actions.assert_title(self.title)


class LogIn(Page):
    """Log in page of the Ubuntu Single Sign On website.

    This is a subclass of the Page object. It extends the assert_page_is_open
    method with additional verifications and adds methods for the actions
    available in this page.

    Instance variables:
    title -- The title of the page.

    """

    title = 'Log in'

    def assert_page_is_open(self):
        """Assert that the page is open."""
        super(LogIn, self).assert_page_is_open()
        sst.actions.assert_element(tag='h1', text='Ubuntu Single Sign On')
        sst.actions.assert_element(tag='h2', text='Are you new?')

    def log_in_to_site_recognized(self, user=None):
        """Fill the log in form and continue to the site that requested it.

        Keyword arguments:
        user -- The user credentials. It must have the attributes email and
            password. If None is passed as the user, it means that the user
            has already started session on the identity provider and it's not
            necessary to enter the credentials again.

        """
        self._log_in(user)

    def log_in_to_site_not_recognized(self, user=None):
        """Fill the log in form and continue to the next step.

        As the site is not recognized, the next step is the page where the
        user can select the information that will be send to the site.

        Keyword arguments:
        user -- The user credentials. It must have the attributes email and
            password. If None is passed as the user, it means that the user
            has already started session on the identity provider and it's not
            necessary to enter the credentials again.

        """
        self._log_in(user)
        return SiteNotRecognized()

    def _log_in(self, user=None):
        if user is not None:
            sst.actions.wait_for(sst.actions.assert_title, 'Log in')
            self._fill_log_in_form(user.email, user.password)
            self._click_continue_button()
        else:
            # If None is passed as the user, it means that the user has
            # already started session on the identity provider and it's not
            # necessary to enter the credentials again.
            pass

    def _fill_log_in_form(self, email, password):
        sst.actions.write_textfield('id_email', email)
        sst.actions.write_textfield('id_password', password)

    def _click_continue_button(self):
        continue_button = sst.actions.get_element(
            css_class='btn', name='continue')
        sst.actions.click_button(continue_button)

    def go_to_create_new_account(self):
        """Go to the Create new account page."""
        new_account_link = sst.actions.get_element(id='new-account-link')
        sst.actions.click_link(new_account_link)
        return CreateAccount()


class CreateAccount(Page):
    """Create account page of the Ubuntu Single Sign On website.

    This is a subclass of the Page object. It adds methods for the actions
    available in this page.

    Instance variables:
    title -- The title of the page.

    """

    title = 'Create account'

    def create_ubuntu_sso_account(self, user):
        """Fill the new account form and continue to the next step.

        Keyword arguments:
        user -- The user credentials. It must have the attributes email and
            password.

        """
        self._fill_new_account_form(user)
        self._click_continue()

    def _fill_new_account_form(self, user):
        sst.actions.write_textfield('id_displayname', user.full_name)
        sst.actions.write_textfield('id_email', user.email)
        sst.actions.write_textfield('id_password', user.password)
        sst.actions.write_textfield('id_passwordconfirm', user.password)

    def _click_continue(self):
        continue_button = sst.actions.get_element(name='continue')
        sst.actions.click_button(continue_button)


class RegistrationMailSent(Page):
    """Registration mail sent page of the Ubuntu Single Sign On website.

    This is a subclass of the Page object. It extends the assert_page_is_open
    method with additional verifications and adds methods for the actions
    available in this page.

    Instance variables:
    title -- The title of the page.

    """

    title = 'Registration mail sent'

    def confirm_email_to_site_recognized(self, confirmation_code):
        """Confirm email and continue to the site that requested the log in.

        Keyword arguments:
        confirmation_code -- The confirmation code sent to the user email
            address.

        """
        self._confirm_email(confirmation_code)

    def confirm_email_to_site_not_recognized(self, confirmation_code):
        """Enter the confirmation code and continue to the next step.

        As the site is not recognized, the next step is the page where the
        user can select the information that will be send to the site.

        Keyword arguments:
        confirmation_code -- The confirmation code sent to the user email
            address.

        """
        self._confirm_email(confirmation_code)
        return SiteNotRecognized()

    def _confirm_email(self, confirmation_code):
        self._enter_confirmation_code(confirmation_code)
        self._click_continue_button()

    def _enter_confirmation_code(self, confirmation_code):
        confirmation_code_text_field = sst.actions.get_element(
            name='confirmation_code')
        sst.actions.write_textfield(confirmation_code_text_field,
                                    confirmation_code)

    def _click_continue_button(self):
        continue_button = sst.actions.get_element(css_class='btn',
                                                  text='Continue')
        sst.actions.click_button(continue_button)


class ValidateEmail(Page):
    """Validate email address confirmation page.

    This is a subclass of the Page object. It adds methods for the actions
    available in this page.

    Instance variables:
    title -- The title of the page.

    """

    title = "Complete email address validation"

    def __init__(self, user_name):
        self.user_name = user_name
        super(ValidateEmail, self).__init__()

    def _click_continue_button(self):
        continue_button = sst.actions.get_element(css_class='btn',
                                                  name='continue')
        sst.actions.click_button(continue_button)

    def _click_cancel(self):
        cancel_link = sst.actions.get_element(tag='a', text='cancel')
        sst.actions.click_link(cancel_link)

    def confirm(self):
        self._click_continue_button()
        return YourAccount(self.user_name)

    def cancel(self):
        return YourAccount(self.user_name)


class SiteNotRecognized(Page):
    """Site not Recognized page of the Ubuntu Single Sign On website.

    This is a subclass of the Page object. It overrides the assert_page_is_open
    method to check only the first part of the title, and adds methods for the
    actions available in this page.

    Instance variables:
    title -- The regular expression of the title of the page.

    """

    title = 'Authenticate to .+'

    def assert_page_is_open(self):
        """Assert that the page is open.

        We use a regular expression because the title has the URL of the site
        that requested the log in plus some tokens, and we don't need to check
        that.

        """
        sst.actions.assert_title_contains(self.title, regex=True)

    def make_all_information_available_to_website(self):
        """Select all the user available information.

        This information will be send to the site that requested the log in.

        """
        information_checkboxes = self._get_information_checkboxes()
        for checkbox in information_checkboxes:
            sst.actions.set_checkbox_value(checkbox, True)
        return self

    def _get_information_checkboxes(self):
        return sst.actions.get_elements_by_css(
            'form[name="decideform"] > .info-items > .list > li > '
            'input[type="checkbox"]')

    def yes_sign_me_in(self):
        """Accept to sign in to the site not recognized and go back to it."""
        sign_me_in_button = sst.actions.get_element(css_class='btn',
                                                    name='yes')
        sst.actions.click_button(sign_me_in_button)


class YourAccount(Page):
    """Your account page of the Ubuntu Single Sign On website.

    This is a subclass of the Page object. It extends the constructor to
    to receive the user name, and adds methods for the actions available in
    this page.

    Instance variables:
    title -- The title of the page. It's build when the page is instantiated
        using the user name.
    sub_header -- The sub header menu displayed on the pages shown to logged
        in users.

    """

    title = "{0}'s details"

    def __init__(self, user_name):
        self.title = self.title.format(user_name)
        super(YourAccount, self).__init__()
        self.sub_header = _UserSubHeader()


class _UserSubHeader(object):

    def log_out(self):
        """Log out from the web site."""
        sst.actions.click_link('logout-link')
        return YouHaveBeenLoggedOut()


class YouHaveBeenLoggedOut(Page):
    """Your account page of the Ubuntu Single Sign On website.

    This is a subclass of the Page object.

    Instance variables:
    title -- The title of the page. It's build when the page is instantiated
        using the user name.

    """

    title = 'You have been logged out'
