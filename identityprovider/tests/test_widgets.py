# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from datetime import datetime
from django.conf import settings
from django.test import TestCase

from identityprovider.tests.utils import SSOBaseTestCase, patch_settings
from identityprovider.widgets import (
    CommaSeparatedWidget,
    LPUsernameWidget,
    ReadOnlyDateTimeWidget,
    ROAwareSelect,
    ROAwareTextInput,
    StatusWidget,
)


class ROAwareTextInputTestCase(TestCase):

    def setUp(self):
        super(ROAwareTextInputTestCase, self).setUp()
        self.widget = ROAwareTextInput()
        p = patch_settings(READ_ONLY_MODE=False)
        p.start()
        self.addCleanup(p.stop)

    def test_render_when_readonly(self):
        settings.READ_ONLY_MODE = True

        r = self.widget.render('test', None)
        self.assertEqual(r, '<span class="rofield"></span>')

        r = self.widget.render('test', 'value')
        self.assertEqual(r, '<span class="rofield">value</span>')

    def test_render_when_not_readonly(self):
        r = self.widget.render('test', None)
        self.assertEqual(r, '<input type="text" name="test" />')

        r = self.widget.render('test', 'value')
        self.assertEqual(r, '<input type="text" name="test" value="value" />')


class ROAwareSelectTestCase(TestCase):

    def setUp(self):
        super(ROAwareSelectTestCase, self).setUp()
        self.choices = (('1', 'One'), ('2', 'Two'))
        self.widget = ROAwareSelect()
        p = patch_settings(READ_ONLY_MODE=False)
        p.start()
        self.addCleanup(p.stop)

    def test_render_when_readonly(self):
        settings.READ_ONLY_MODE = True

        r = self.widget.render('test', 'value', choices=self.choices)
        self.assertEqual(r, '<span class="rofield"></span>')

    def test_render_when_readonly_selected(self):
        settings.READ_ONLY_MODE = True

        choices = self.choices + (('value', 'The Value'),)
        r = self.widget.render('test', 'value', choices=choices)
        self.assertEqual(r, '<span class="rofield">The Value</span>')

    def test_render_when_not_readonly(self):
        r = self.widget.render('test', 'value', choices=self.choices)
        expected = """<select name="test">
<option value="1">One</option>
<option value="2">Two</option>
</select>"""
        self.assertEqual(r, expected)


class CommaSeparatedWidgetTestCase(TestCase):

    def setUp(self):
        super(CommaSeparatedWidgetTestCase, self).setUp()
        self.choices = (('1', 'One'), ('2', 'Two'), ('3', 'Three'))
        self.widget = CommaSeparatedWidget()

    def test_render_when_value_is_none(self):
        r = self.widget.render('test', None, choices=self.choices)
        self.assertTrue('checked' not in r)

    def test_render_when_value_is_list(self):
        r = self.widget.render('test', ['1', '2'], choices=self.choices)
        self.assertEqual(r.count('checked="checked"'), 2)

    def test_render_when_value_is_comma_separated_list(self):
        r = self.widget.render('test', "1,2", choices=self.choices)
        self.assertEqual(r.count('checked="checked"'), 2)


class StatusWidgetTestCase(TestCase):

    def setUp(self):
        super(StatusWidgetTestCase, self).setUp()
        self.choices = (('1', 'One'), ('2', 'Two'))
        self.widget = StatusWidget()

    def test_render_not_date_status_set(self):
        r = self.widget.render('test', 'value', choices=self.choices)
        expected = """<select name="test">
<option value="1">One</option>
<option value="2">Two</option>
</select> """
        self.assertEqual(r, expected)

    def test_render_date_status_set(self):
        self.widget.date_status_set = datetime(2010, 01, 01)
        r = self.widget.render('test', 'value', choices=self.choices)
        expected = """<select name="test">
<option value="1">One</option>
<option value="2">Two</option>
</select> Set on 2010-01-01 00:00:00"""
        self.assertEqual(r, expected)


class ReadOnlyDateTimeWidgetTestCase(TestCase):

    def setUp(self):
        super(ReadOnlyDateTimeWidgetTestCase, self).setUp()
        self.widget = ReadOnlyDateTimeWidget()

    def test_render_string(self):
        self.widget.value = 'value'
        r = self.widget.render('test', None)
        self.assertEqual(r, 'value')

    def test_render_int(self):
        self.widget.value = 4
        r = self.widget.render('test', None)
        self.assertEqual(r, '4')

    def test_render_bool(self):
        self.widget.value = False
        r = self.widget.render('test', None)
        self.assertEqual(r, 'False')

    def test_render_datetime(self):
        self.widget.value = datetime(2010, 01, 01)
        r = self.widget.render('test', None)
        self.assertEqual(r, '2010-01-01 00:00:00')


class LPUsernameWidgetTestCase(SSOBaseTestCase):

    def setUp(self):
        super(LPUsernameWidgetTestCase, self).setUp()
        self.widget = LPUsernameWidget()
        self.account = self.factory.make_account()
        assert self.account.person is None
        self.widget.account = self.account

    def test_render_account_with_person(self):
        self.factory.make_person(account=self.account)
        assert self.account.person is not None

        r = self.widget.render('test', None)
        widget = '<a href="https://launchpad.net/~{name}">{name}</a>'.format(
            name=self.widget.account.person.name)
        self.assertEqual(r, widget)

    def test_render_no_account(self):
        # unlink account
        self.widget.account = None
        r = self.widget.render('test', None)
        self.assertEqual(r, '')

    def test_render_account_no_person(self):
        r = self.widget.render('test', None)
        self.assertEqual(r, '')
