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

import os
import tempfile

import bs4
import mock
import sst.runtests
from testtools.matchers import Contains

import u1testutils.logging
import u1testutils.sst


class StringHTMLPage(u1testutils.sst.Page):

    def __init__(self, page_source):
        self.page_source = page_source
        # We don't check the page because some tests will need it to have
        # errors.
        super(StringHTMLPage, self).__init__(check=False)

    def open_page(self, page_source=None):
        if not page_source:
            page_source = self.page_source
        page_file = tempfile.NamedTemporaryFile(delete=False)
        self.url_path = page_file.name
        page_file.write(page_source)
        page_file.close()
        sst.actions.go_to('file://{0}'.format(page_file.name))
        # We delete the temporary page file as it's not longer needed.
        os.remove(page_file.name)


class StringPageSSTTestCase(sst.runtests.SSTTestCase):

    page_source = (
        """
        <html>
          <body>
          Test.
          <body>
        </html>
        """
    )

    xserver_headless = True

    def setUp(self):
        super(StringPageSSTTestCase, self).setUp()
        self.page = StringHTMLPage(self.page_source)


class AssertPageTestCase(
        StringPageSSTTestCase, u1testutils.logging.LogHandlerTestCase):

    page_source = (
        """
        <html>
          <head>
            <title>Test title</title>
          </head>
          <body>
            <h1>Test h1 1</h1>
              <h2>Test h2 1</h2>
                <p>Test paragraph 1</p>
            <h1>Test h1 2</h1>
              <h2>Test h2 2</h2>
                <p>Test paragraph 2</p>
          <body>
        </html>
        """
    )

    def setUp(self):
        super(AssertPageTestCase, self).setUp()
        self.page = StringHTMLPage(self.page_source)

    def test_correct_page_is_open(self):
        self.page.title = 'Test title'
        self.page.headings1 = ['Test h1 1', 'Test h1 2']
        self.page.headings2 = ['Test h2 1', 'Test h2 2']
        self.page.open_page()
        self.page.assert_page_is_open()

    def test_wrong_title(self):
        self.page.title = 'Wrong title'
        self.assertRaises(AssertionError, self.page.assert_title)

    def test_wrong_url_path(self):
        self.page.url_path = 'Wrong path'
        self.assertRaises(AssertionError, self.page.assert_url_path)

    def test_wrong_url_path_with_a_match(self):
        self.page.url_path = '/test_path'
        with mock.patch('sst.actions.browser') as mock_browser:
            mock_url = 'http://test_netloc/wrong/test_path/wrong'
            mock_browser.current_url = mock_url
            self.assertRaises(AssertionError, self.page.assert_url_path)

    def test_wrong_url_path_with_a_suffix(self):
        self.page.url_path = '/test_path'
        with mock.patch('sst.actions.browser') as mock_browser:
            mock_url = 'http://test_netloc/test_path/wrong'
            mock_browser.current_url = mock_url
            self.assertRaises(AssertionError, self.page.assert_url_path)

    def test_assert_url_path_with_query(self):
        self.page.url_path = '/test_path'
        with mock.patch('sst.actions.browser') as mock_browser:
            mock_browser.current_url = 'http://test_netloc/test_path?query'
            self.page.assert_url_path()

    def test_wrong_headings1_text(self):
        self.page.headings1 = ['Test h1 1', 'Wrong h1']
        self.page.open_page()
        error = self.assertRaises(AssertionError, self.page.assert_headings1)
        self.assertEqual(
            error.message,
            'Expected elements texts: Test h1 1, Wrong h1\n'
            'Actual elements texts: Test h1 1, Test h1 2')

    def test_wrong_headings2_text(self):
        self.page.headings2 = ['Test h2 1', 'Wrong h2']
        self.page.open_page()
        error = self.assertRaises(AssertionError, self.page.assert_headings2)
        self.assertEqual(
            error.message,
            'Expected elements texts: Test h2 1, Wrong h2\n'
            'Actual elements texts: Test h2 1, Test h2 2')

    def test_assert_page_with_visible_oops(self):
        soup = bs4.BeautifulSoup(self.page_source)
        oops_element = soup.new_tag('div')
        oops_element['class'] = 'yui3-error-visible'
        oops_element.string = 'Test oops'
        soup.body.append(oops_element)
        # We don't need to make the assertions for the rest of the page.
        self.page.assert_title = lambda: None
        self.page.assert_url_path = lambda: None
        self.page.headings1 = []
        self.page.headings2 = []

        self.page.open_page(page_source=str(soup))
        error = self.assertRaises(
            AssertionError, self.page.assert_page_is_open)
        self.assertThat(error.message, Contains('Test oops'))

    def test_assert_wrong_page_with_error(self):
        soup = bs4.BeautifulSoup(self.page_source)
        error_element = soup.new_tag('span')
        error_element['class'] = 'error'
        error_element.string = 'Test error'
        soup.body.append(error_element)
        self.page.title = 'Wrong title'
        self.page.open_page(page_source=str(soup))
        self.assertRaises(
            AssertionError, self.page.assert_page_is_open)
        self.assertLogLevelContains('ERROR', 'Test error')
