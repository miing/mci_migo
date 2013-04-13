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
import re
import urlparse

import sst.actions

from functools import wraps


logger = logging.getLogger('User test')


def log_action(log_func):
    """Decorator to log the call of an action method."""

    def middle(f):

        @wraps(f)
        def inner(instance, *args, **kwargs):
            class_name = str(instance.__class__.__name__)
            docstring = f.__doc__
            if docstring:
                docstring = docstring.split('\n')[0].strip()
            else:
                docstring = f.__name__
            log_line = '%r: %r. Arguments %r. Keyword arguments: %r.'
            log_func(log_line, class_name, docstring, args, kwargs)
            return f(instance, *args, **kwargs)

        return inner

    return middle


class Page(object):
    """Base class for the page objects used in acceptance testing.

    Instance variables:
    title -- The title of the page.
    url_path -- The path of the page. It is a regular expression, so you can
        use python's re special characters, but you will have to escape them
        if they are part of the path. The URL structure is explained in the
        documentation of python's urlparse.
    headings1 -- A list with the expected text of the h1 elements. If it's
        empty, the h1 elements will not be checked.
    headings2 -- A list with the expected text of the h2 elements. If it's
        empty, the h2 elements will not be checked.

    """

    title = None
    url_path = None
    headings1 = []
    headings2 = []

    def __init__(self, check=True):
        super(Page, self).__init__()
        if check:
            self.assert_page_is_open()

    @log_action(logging.info)
    def open_page(self):
        """Open the page."""
        assert self.url_path is not None
        sst.actions.go_to(self.url_path)
        return self

    def assert_page_is_open(self):
        """Assert that the page is open and that no oops are displayed."""
        try:
            assert not self._is_oops_displayed(), \
                'An oops error is displayed: {0}'.format(
                    self._get_oops_element().text)
            self.assert_title()
            self.assert_url_path()
            if self.headings1:
                self.assert_headings1()
            if self.headings2:
                self.assert_headings2()
        except AssertionError:
            self._log_errors()
            raise

    def _is_oops_displayed(self):
        try:
            self._get_oops_element()
            return True
        except AssertionError:
            return False

    def _get_oops_element(self):
        # TODO this works for U1. Does it work the same for pay and SSO?
        oops_class = 'yui3-error-visible'
        return sst.actions.get_element(css_class=oops_class)

    def assert_title(self):
        """Assert the title of the page."""
        sst.actions.assert_title(self.title)

    def assert_url_path(self):
        """Assert the path of the page URL."""
        current_url = sst.actions.browser.current_url
        current_url_path = urlparse.urlparse(current_url).path
        # Make sure that there are no more characters at the end of the path.
        url_path_regexp = self.url_path + '$'
        assert re.match(url_path_regexp, current_url_path)

    def assert_headings1(self):
        """Assert the h1 elements of the page."""
        self._assert_elements_text('h1', self.headings1)

    def _assert_elements_text(self, tag, expected_texts):
        elements_text = self._get_elements_text(tag)
        assert elements_text == expected_texts, \
            'Expected elements texts: {0}\n' \
            'Actual elements texts: {1}'.format(
                ', '.join(expected_texts), ', '.join(elements_text))

    def _get_elements_text(self, tag=None, css_class=None):
        get_text = lambda x: x.text
        return map(get_text, sst.actions.get_elements(
            tag=tag, css_class=css_class))

    def assert_headings2(self):
        """Assert the h2 elements of the page."""
        self._assert_elements_text('h2', self.headings2)

    def _log_errors(self):
        if sst.actions.exists_element(css_class='error'):
            logger.error(
                ', '.join(self._get_elements_text(css_class='error')))
