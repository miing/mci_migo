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

import contextlib
import logging
import mock
import testtools

import u1testutils.logging

from u1testutils.sst import log_action, Page


class PageWithoutBrowser(Page):
    """Page double that allows us to test instantiation without a browser."""

    def __init__(self, *args, **kwargs):
        self.page_opened = False
        self.url_path = '/test/path/'
        super(PageWithoutBrowser, self).__init__(*args, **kwargs)

    def _open_page(self):
        self.page_opened = True
        with mock.patch('sst.actions.go_to'):
            super(PageWithoutBrowser, self)._open_page()

    def assert_page_is_open(self):
        assert self.page_opened
        # do not call super()


class PageWithoutCheck(Page):

    def __init__(self):
        # We overwrite the parent constructor to do nothing, because on the
        # parent it will try to assert that the page is open. Here we don't
        # have a real page, but we can test the different page methods with
        # mocks if we skip the check on init. We also have acceptance tests
        # that use real pages for full coverage.
        pass


class InitPageTestCase(testtools.TestCase):

    def test_open_page_on_instantiation(self):
        page = PageWithoutBrowser(open_page=True)
        self.assertTrue(page.page_opened)

    def test_assert_closed_page_on_instantiation(self):
        self.assertRaises(AssertionError, PageWithoutBrowser, open_page=False)

    def test_open_page_without_path(self):
        page = PageWithoutBrowser(open_page=True)
        page.url_path = None
        self.assertRaises(AssertionError, page._open_page)

    def test_open_page_with_path_regex(self):
        page = PageWithoutBrowser(open_page=True)
        page.url_path = '/test/.*'
        page.is_url_path_regex = True
        self.assertRaises(ValueError, page._open_page)

    def test_open_page_goes_to_url_path(self):
        page = PageWithoutCheck()
        page.url_path = '/test/path'
        with mock.patch('sst.actions.go_to') as mock_action:
            returned_page = page._open_page()
        mock_action.assert_called_with('/test/path')
        self.assertEquals(page, returned_page)

    def test_assert_page_is_open(self):
        # All the mocked methods have acceptance tests.
        with contextlib.nested(
            mock.patch.object(Page, '_is_oops_displayed', return_value=False),
            mock.patch.object(Page, 'assert_title'),
            mock.patch.object(Page, 'assert_url_path'),
        ) as mock_checks:
            PageWithoutCheck().assert_page_is_open()
        for mock_check in mock_checks:
            mock_check.assert_called_once_with()


class PageWithOnlyHeadingsAssertions(PageWithoutCheck):

        def assert_title(self):
            pass

        def assert_url_path(self):
            pass

        def _is_oops_displayed(self):
            pass


class PageHeadingsTestCase(testtools.TestCase):

    def test_assert_page_without_headings1_check(self):
        with mock.patch.object(Page, 'assert_headings1') as mock_assert:
            page = PageWithOnlyHeadingsAssertions()
            page.headings1 = []
            page.assert_page_is_open()
            assert not mock_assert.called

    def test_assert_page_without_headings2_check(self):
        with mock.patch.object(Page, 'assert_headings2') as mock_assert:
            page = PageWithOnlyHeadingsAssertions()
            page.headings2 = []
            page.assert_page_is_open()
            assert not mock_assert.called


class PageWithLogDecorator(PageWithoutCheck):

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
        self.page = PageWithLogDecorator()

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
