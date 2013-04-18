# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import re
from django import forms
from django.utils.translation import ugettext as _

from identityprovider.widgets import CommaSeparatedWidget


class CommaSeparatedField(forms.MultipleChoiceField):
    widget = CommaSeparatedWidget

    def clean(self, value):
        return ','.join(super(CommaSeparatedField, self).clean(value))


class OATHPasswordField(forms.CharField):
    """A string of between 6 or 8 digits."""
    widget = forms.widgets.TextInput(attrs={
        'autocomplete': 'off',
        'autofocus': 'autofocus'
    })
    SIX = re.compile('[0-9]{6}$')
    EIGHT = re.compile('[0-9]{8}$')

    def clean(self, value):
        """Validate otp and detect type"""
        # remove any whitespace from the string
        if value:
            value = value.strip().replace(' ', '')
        value = super(OATHPasswordField, self).clean(value)
        if self.SIX.match(value):
            return value
        elif self.EIGHT.match(value):
            return value
        raise forms.ValidationError(
            _('Please enter a 6-digit or 8-digit one-time password.'))
