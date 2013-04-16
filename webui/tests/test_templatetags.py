# Copyright 2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from unittest import TestCase

from django.conf import settings
from django.template import (
    Context,
    Template,
)
from mock import patch


CASES = ({
    # If the first file has a .css extension, css links are rendered for all.
    "in": "'a/b/foo.css' 'd/e/goo.doesntmatter'",
    "out_no_combine": (
        '<link href="/static/a/b/foo.css" rel="stylesheet"'
        ' type="text/css" media="screen" />\n'
        '<link href="/static/d/e/goo.doesntmatter" rel="stylesheet"'
        ' type="text/css" media="screen" />'),
    "out_combine": (
        '<link href="/combo/?a/b/foo.css&d/e/goo.doesntmatter" '
        'rel="stylesheet" type="text/css" media="screen" />'),
}, {
    # If the first file has a .js extension, js links are rendered for all.
    "in": "'a/b/foo.js' 'd/e/goo.doesntmatter'",
    "out_no_combine": (
        '<script type="text/javascript" src="/static/a/b/foo.js">'
        '</script>\n'
        '<script type="text/javascript" src="/static/d/e/goo.doesntmatter">'
        '</script>'),
    "out_combine": (
        '<script type="text/javascript"'
        ' src="/combo/?a/b/foo.js&d/e/goo.doesntmatter"></script>'),
}, {
    # If the extension of the first file is neither js or css, css is rendered.
    "in": "'a/b/un.known' 'd/e/doesntmatter.js'",
    "out_no_combine": (
        '<link href="/static/a/b/un.known" rel="stylesheet"'
        ' type="text/css" media="screen" />\n'
        '<link href="/static/d/e/doesntmatter.js" rel="stylesheet"'
        ' type="text/css" media="screen" />'),
    "out_combine": (
        '<link href="/combo/?a/b/un.known&d/e/doesntmatter.js" '
        'rel="stylesheet" type="text/css" media="screen" />'),
}, {
    # A single css file is rendered to a normal link either way.
    "in": "'a/b/foo.css'",
    "out_no_combine": (
        '<link href="/static/a/b/foo.css" rel="stylesheet"'
        ' type="text/css" media="screen" />'),
    "out_combine": (
        '<link href="/static/a/b/foo.css" rel="stylesheet"'
        ' type="text/css" media="screen" />'),
}, {
    # A single js file is rendered to a normal link either way.
    "in": "'a/b/foo.js'",
    "out_no_combine": (
        '<script type="text/javascript" src="/static/a/b/foo.js">'
        '</script>'),
    "out_combine": (
        '<script type="text/javascript" src="/static/a/b/foo.js">'
        '</script>'),
}, {
    # A prefix can be used for convenience.
    "in": "'foo.js' 'goo.js' prefix='a/b'",
    "out_no_combine": (
        '<script type="text/javascript" src="/static/a/b/foo.js">'
        '</script>\n'
        '<script type="text/javascript" src="/static/a/b/goo.js">'
        '</script>'),
    "out_combine": (
        '<script type="text/javascript"'
        ' src="/combo/?a/b/foo.js&a/b/goo.js"></script>'),
})


class ComboTestCase(TestCase):

    def test_combine_false(self):
        """Individual tags are outputted when COMBINE=False."""
        with patch.multiple(settings, COMBINE=False, STATIC_URL='/static/'):
            for case in CASES:
                result = Template(
                    "{% load combo %}"
                    "{% combo " + case['in'] + " %}").render(Context())

                self.assertEqual(case['out_no_combine'], result)

    def test_combine_true(self):
        """A single tag is outputted when COMBINE=True."""
        with patch.multiple(settings, COMBINE=True, COMBO_URL='/combo/',
                            STATIC_URL='/static/'):
            for case in CASES:
                result = Template(
                    "{% load combo %}"
                    "{% combo " + case['in'] + " %}").render(Context())

                self.assertEqual(case['out_combine'], result)
