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

import logging
import mock
import testtools

import u1testutils.logging

from u1testutils.sst import log_action, Page


class PageTestCase(testtools.TestCase):

    def test_assert_page_is_open_on_instantiation(self):
        with mock.patch.object(Page, 'assert_page_is_open') as mock_assert:
            Page()
            mock_assert.assert_called_once_with()

    def test_instantiate_page_without_check(self):
        with mock.patch.object(Page, 'assert_page_is_open') as mock_assert:
            Page(check=False)
            assert not mock_assert.called

    def test_open_page(self):
        page = Page(check=False)
        page.url_path = '/test/path'
        with mock.patch('sst.actions.go_to') as mock_action:
            returned_page = page.open_page()
        mock_action.assert_called_with('/test/path')
        self.assertEquals(page, returned_page)

    def test_open_page_without_path(self):
        page = Page(check=False)
        page.url_path = None
        self.assertRaises(AssertionError, page.open_page)


class PageWithOnlyHeadingsAssertions(Page):

        def assert_title(self):
            pass

        def assert_url_path(self):
            pass

        def _is_oops_displayed(self):
            pass


class PageHeadingsTestCase(testtools.TestCase):

    def test_assert_page_without_headings1_check(self):
        with mock.patch.object(Page, 'assert_headings1') as mock_assert:
            page = PageWithOnlyHeadingsAssertions(check=False)
            page.headings1 = []
            page.assert_page_is_open()
            assert not mock_assert.called

    def test_assert_page_without_headings2_check(self):
        with mock.patch.object(Page, 'assert_headings2') as mock_assert:
            page = PageWithOnlyHeadingsAssertions(check=False)
            page.headings2 = []
            page.assert_page_is_open()
            assert not mock_assert.called


class PageWithLogDecorator(Page):

    @log_action(logging.info)
    def do_something_without_docstring(self, *args, **kwargs):
        pass

    @log_action(logging.info)
    def do_something_with_docstring(self, *args, **kwargs):
        """Do something with docstring."""
        pass

    @log_action(logging.info)
    def do_something_with_multiline_docstring(self, *args, **kwargs):
        """Do something with a multiline docstring.

        This should not be logged.
        """
        pass


class PageLoggingTestCase(u1testutils.logging.LogHandlerTestCase):

    def setUp(self):
        super(PageLoggingTestCase, self).setUp()
        self.root_logger.setLevel(logging.INFO)
        self.page = PageWithLogDecorator(check=False)

    def test_logged_action_without_docstring(self):
        self.page.do_something_without_docstring(
            'arg1', 'arg2', arg3='arg3', arg4='arg4')
        self.assertLogLevelContains(
            'INFO',
            "'PageWithLogDecorator': 'do_something_without_docstring'. "
            "Arguments ('arg1', 'arg2'). "
            "Keyword arguments: {'arg3': 'arg3', 'arg4': 'arg4'}.")

    def test_logged_action_with_docstring(self):
        self.page.do_something_with_docstring(
            'arg1', 'arg2', arg3='arg3', arg4='arg4')
        self.assertLogLevelContains(
            'INFO',
            "'PageWithLogDecorator': 'Do something with docstring.'. "
            "Arguments ('arg1', 'arg2'). "
            "Keyword arguments: {'arg3': 'arg3', 'arg4': 'arg4'}.")

    def test_logged_action_with_multiline_docstring(self):
        self.page.do_something_with_multiline_docstring(
            'arg1', 'arg2', arg3='arg3', arg4='arg4')
        self.assertLogLevelContains(
            'INFO',
            "'PageWithLogDecorator': "
            "'Do something with a multiline docstring.'. "
            "Arguments ('arg1', 'arg2'). "
            "Keyword arguments: {'arg3': 'arg3', 'arg4': 'arg4'}.")
