# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from unittest import TestCase

from identityprovider.templatetags.google_analytics import expand_ga_commands
from identityprovider.templatetags.static_url import static_url
from identityprovider.tests.utils import patch_settings


SNIPPETS = [
    None,
    '',
    'not valid json'
    '"); alert("gotcha!"); //'
    '\'); alert(\'gotcha!\'); //'
    '"Not a json list"'
    '"\'); alert(\'JSON gotcha!\'); //"'
    '["List of strings"]'
    '[[]]',
    '[["omg", function() { alert("gotcha!"); }]]'
    '[["nothing", "move along"], ["just a bit conspicuous", 42]]'
    '[["something", "with multiple\nlines"]]'
]


class GACommandsTestCase(TestCase):

    def test_invalid_snippets(self):
        for snippet in SNIPPETS:
            self.assertEqual('', expand_ga_commands(snippet))

    def test_valid_snippets(self):
        for snippet, expected in [
                ('[["foo", "bar"]]', "_gaq.push(['foo', 'bar']);"),
                ('[["foo", "bar"], ["baz", "zot"]]',
                 "_gaq.push(['foo', 'bar']);\n_gaq.push(['baz', 'zot']);"),
        ]:
            self.assertEqual(expected, expand_ga_commands(snippet))

    def test_unicode_coercion(self):
        snippet = '[["foo", "bar"]]'
        self.assertIsInstance(expand_ga_commands(snippet), unicode)


class StaticUrlTestCase(TestCase):

    def test_returns_empty_string_when_setting_missing(self):
        self.assertEqual(static_url('does_not_exist'), '')

    def test_returns_setting_when_absolute_url(self):
        url = 'http://test.com/support'
        with patch_settings(TEST_SUPPORT_URL=url):
            self.assertEqual(static_url('test_support'), url)

    def test_returns_setting_when_relative_url(self):
        url = '/+relative'
        with patch_settings(RELATIVE_URL=url):
            self.assertEqual(static_url('relative'), url)
