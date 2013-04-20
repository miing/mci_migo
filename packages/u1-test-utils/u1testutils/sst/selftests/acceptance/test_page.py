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

    def __init__(self, page_source, title, headings1, headings2, url_path,
                 is_url_path_regex):
        self.page_source = page_source
        self.title = title
        self.headings1 = headings1
        self.headings2 = headings2
        page_file_name = None
        if url_path:
            self.url_path = url_path
        else:
            page_file_name = self._make_temp_page()
            self.url_path = page_file_name
        self.is_url_path_regex = is_url_path_regex
        try:
            super(StringHTMLPage, self).__init__(open_page=True)
        finally:
            if page_file_name:
                os.remove(page_file_name)

    def _make_temp_page(self):
        page_file = tempfile.NamedTemporaryFile(delete=False)
        page_file.write(self.page_source)
        page_file.close()
        return page_file.name


class AssertPageTestCase(
        sst.runtests.SSTTestCase, u1testutils.logging.LogHandlerTestCase):

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

    base_url = 'file://'
    xserver_headless = True

    def setUp(self):
        super(AssertPageTestCase, self).setUp()
        self.page_kwargs = dict(
            page_source=self.page_source,
            title='Test title',
            headings1=['Test h1 1', 'Test h1 2'],
            headings2=['Test h2 1', 'Test h2 2'],
            # If the url path is not specifiec, it will be set to the name of
            # the temp file.
            url_path=None,
            is_url_path_regex=False
        )

    def test_corect_page_is_open(self):
        StringHTMLPage(**self.page_kwargs)
        # No error means the page was opened and asserted.

    def test_wrong_title(self):
        self.page_kwargs['title'] = 'Wrong title'
        self.assertRaises(AssertionError, StringHTMLPage, **self.page_kwargs)

    def test_wrong_url_path(self):
        self.page_kwargs['url_path'] = 'Wrong path'
        self.assertRaises(AssertionError, StringHTMLPage, **self.page_kwargs)

    def test_wrong_headings1_text(self):
        self.page_kwargs['headings1'] = ['Test h1 1', 'Wrong h1']
        error = self.assertRaises(
            AssertionError, StringHTMLPage, **self.page_kwargs)
        self.assertEqual(
            error.message,
            'Expected elements texts: Test h1 1, Wrong h1\n'
            'Actual elements texts: Test h1 1, Test h1 2')

    def test_wrong_headings2_text(self):
        self.page_kwargs['headings2'] = ['Test h2 1', 'Wrong h2']
        error = self.assertRaises(
            AssertionError, StringHTMLPage, **self.page_kwargs)
        self.assertEqual(
            error.message,
            'Expected elements texts: Test h2 1, Wrong h2\n'
            'Actual elements texts: Test h2 1, Test h2 2')

    def test_assert_url_path_with_regexp(self):
        page = StringHTMLPage(**self.page_kwargs)
        page.url_path = '.+'
        page.is_url_path_regex = True
        page.assert_url_path()

    def test_wrong_url_path_with_a_match(self):
        page = StringHTMLPage(**self.page_kwargs)
        page.url_path = '/test_path'
        page.is_url_path_regex = True
        with mock.patch('sst.actions.get_current_url') as mock_action:
            mock_url = 'http://test_netloc/wrong/test_path/wrong'
            mock_action.return_value = mock_url
            self.assertRaises(AssertionError, page.assert_url_path)

    def test_wrong_url_path_with_a_suffix(self):
        page = StringHTMLPage(**self.page_kwargs)
        page.url_path = '/test_path'
        page.is_url_path_regex = True
        with mock.patch('sst.actions.get_current_url') as mock_action:
            mock_url = 'http://test_netloc/test_path/wrong'
            mock_action.return_value = mock_url
            self.assertRaises(AssertionError, page.assert_url_path)

    def test_assert_url_path_with_query(self):
        page = StringHTMLPage(**self.page_kwargs)
        page.url_path = '/test_path'
        with mock.patch('sst.actions.get_current_url') as mock_action:
            mock_action.return_value = 'http://test_netloc/test_path?query'
            page.assert_url_path()

    def test_assert_page_with_visible_oops(self):
        soup = bs4.BeautifulSoup(self.page_source)
        oops_element = soup.new_tag('div')
        oops_element['class'] = 'yui3-error-visible'
        oops_element.string = 'Test oops'
        soup.body.append(oops_element)
        self.page_kwargs['page_source'] = str(soup)
        error = self.assertRaises(
            AssertionError, StringHTMLPage, **self.page_kwargs)
        self.assertThat(error.message, Contains('Test oops'))

    def test_assert_wrong_page_with_error(self):
        soup = bs4.BeautifulSoup(self.page_source)
        error_element = soup.new_tag('span')
        error_element['class'] = 'error'
        error_element.string = 'Test error'
        soup.body.append(error_element)
        self.page_kwargs['page_source'] = str(soup)
        self.page_kwargs['title'] = 'Wrong title'
        self.assertRaises(
            AssertionError, StringHTMLPage, **self.page_kwargs)
        self.assertLogLevelContains('ERROR', 'Test error')
