# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from itertools import chain
from django.forms.widgets import (
    CheckboxSelectMultiple,
    Select,
    TextInput,
    Widget,
)
from django.conf import settings
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _


def read_only_markup(value):
    if value is None:
        value = ''
    markup = '<span class="rofield">%s</span>' % value
    return mark_safe(markup)


def account_to_lp_link(account):
    if account and account.person:
        return ('<a href="https://launchpad.net/~%s">%s</a>' %
                (account.person.name, account.person.name))
    return ''


class ROAwareTextInput(TextInput):
    def render(self, name, value, attrs=None):
        if settings.READ_ONLY_MODE:
            return read_only_markup(value)
        else:
            return super(ROAwareTextInput, self).render(name, value, attrs)


class ROAwareSelect(Select):
    def render(self, name, value, attrs=None, choices=()):
        if settings.READ_ONLY_MODE:
            label = ''
            for option_value, option_label in chain(self.choices, choices):
                if option_value == value:
                    label = option_label
                    break
            return read_only_markup(label)
        else:
            return super(ROAwareSelect, self).render(name, value, attrs,
                                                     choices)


class CommaSeparatedWidget(CheckboxSelectMultiple):
    def render(self, name, value, attrs=None, choices=()):
        if value is None:
            value = ''
        if isinstance(value, list):
            vals = value
        else:
            vals = value.split(',')
        return super(CommaSeparatedWidget, self).render(
            name, vals, attrs, choices)


class StatusWidget(Select):
    date_status_set = None

    def render(self, name, value, attrs=None, choices=()):
        select = super(StatusWidget, self).render(name, value, attrs, choices)
        if self.date_status_set:
            status_date = _("Set on %s") % self.date_status_set
        else:
            status_date = ""
        return mark_safe("%s %s" % (select, status_date))


class ReadOnlyDateTimeWidget(Widget):
    value = None

    def render(self, name, value, attrs=None):
        return str(self.value)


class LPUsernameWidget(Widget):
    account = None

    def render(self, name, value, attrs=None):
        return mark_safe(account_to_lp_link(self.account))
