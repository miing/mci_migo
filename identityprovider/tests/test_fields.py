# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django import forms
from django.test import TestCase

from identityprovider.fields import (
    CommaSeparatedField,
    OATHPasswordField,
)


class CommaSeparatedFieldTestCase(TestCase):

    def test_clean(self):
        choices = (('1', 'One'), ('2', 'Two'), ('3', 'Three'))
        field = CommaSeparatedField(choices=choices)
        value = field.clean(["1", "2", "3"])
        self.assertEqual(value, "1,2,3")


class OATHPasswordFieldTestCase(TestCase):

    def do_clean(self, value):
        field = OATHPasswordField()
        return field.clean(value)

    def test_too_short_not_accepted(self):
        self.assertRaises(forms.ValidationError, self.do_clean, '1')
        self.assertRaises(forms.ValidationError, self.do_clean, '12')
        self.assertRaises(forms.ValidationError, self.do_clean, '123')
        self.assertRaises(forms.ValidationError, self.do_clean, '1234')
        self.assertRaises(forms.ValidationError, self.do_clean, '12345')

    def test_too_long_not_accepted(self):
        self.assertRaises(forms.ValidationError, self.do_clean, '123456789')

    def test_7_digits_not_accepted(self):
        self.assertRaises(forms.ValidationError, self.do_clean, '1234567')

    def test_valid_lengths_accepted(self):
        self.assertEqual(self.do_clean('123456'), '123456')
        self.assertEqual(self.do_clean('12345678'), '12345678')

    def test_non_digits_not_accepted(self):
        self.assertRaises(forms.ValidationError, self.do_clean, '12345X')
        self.assertRaises(forms.ValidationError, self.do_clean, '1234567X')

    def test_whitespace_accepted(self):
        self.assertEqual(self.do_clean(' 123456'), '123456')
        self.assertEqual(self.do_clean('123456 '), '123456')
        self.assertEqual(self.do_clean('123 456'), '123456')
