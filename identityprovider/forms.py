# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import logging

from django import forms
from django.core.urlresolvers import reverse
from django.forms import Form, fields, widgets
from django.utils import translation
from django.utils.translation import ugettext as _

from identityprovider.const import (
    AX_DATA_FIELDS,
    AX_DATA_LABELS,
)
from identityprovider.models import (
    Account,
    EmailAddress,
    verify_token_string,
    get_team_memberships_for_user,
)
from identityprovider.models.const import EmailStatus
from identityprovider.utils import (
    get_current_brand,
)
from identityprovider.validators import (
    PASSWORD_POLICY_HELP_TEXT,
    validate_password_policy,
)
from identityprovider.fields import OATHPasswordField
from identityprovider.widgets import (
    ROAwareTextInput,
    ROAwareSelect,
)


logger = logging.getLogger('sso')

TWOFACTOR_CHOICES = (
    (True, _('Always require an authentication device')),
    (False, _('Require only when logging in to sites that request it')),
)

default_errors = {
    'required': _(u'Required field.'),
    'invalid': _(u'Invalid value.'),
}

email_errors = {
    'required': _(u'Required field.'),
    # Translators: This is used on all email-related input forms.
    'invalid': _(u'Invalid email.'),
}

tos_error = {
    'required': _(
        u'Check the box to indicate that you agree with our terms of use:'
    ),
}


class GenericEmailForm(forms.Form):
    email_widget_conf = {'class': 'textType', 'size': '26'}

    # add placeholder, autofocus and email type for the u1 brand
    if get_current_brand() == 'ubuntuone':
        email_widget_conf['placeholder'] = _('Ubuntu One email')
        email_widget_conf['autofocus'] = 'autofocus'
        email_widget = widgets.Input(attrs=email_widget_conf)
        email_widget.input_type = 'email'
    else:
        email_widget = widgets.TextInput(attrs=email_widget_conf)

    email = fields.EmailField(
        error_messages=email_errors,
        widget=email_widget,
    )


class LoginForm(GenericEmailForm):
    password_widget_conf = {
        'class': 'textType',
        'size': ' 26',
    }

    if get_current_brand() == 'ubuntuone':
        password_widget_conf['placeholder'] = _('Password')

    password = fields.CharField(
        error_messages=default_errors,
        widget=widgets.PasswordInput(attrs=password_widget_conf),
    )


class TwoFactorLoginForm(LoginForm):
    """A form that requires both password and 2factor oath token for login."""
    oath_token = OATHPasswordField()


class TwoFactorForm(forms.Form):
    """This form shows *only* the two factor oath token field."""
    oath_token = OATHPasswordField()


class ResetPasswordForm(forms.Form):

    password_widget_conf = {
        'class': 'textType',
        'size': '20',
    }
    passwordconfirm_widget_conf = {
        'class': 'textType',
        'size': '20',
    }

    if get_current_brand() == 'ubuntuone':
        password_widget_conf['placeholder'] = _(
            'Password with at least 8 characters'
        )

        passwordconfirm_widget_conf['placeholder'] = _('Retype password')

    password = fields.CharField(
        error_messages=default_errors,
        help_text=PASSWORD_POLICY_HELP_TEXT,
        validators=[validate_password_policy],
        widget=widgets.PasswordInput(attrs=password_widget_conf),
    )
    passwordconfirm = fields.CharField(
        error_messages=default_errors,
        widget=widgets.PasswordInput(attrs=passwordconfirm_widget_conf),
    )

    def clean(self):
        cleaned_data = self.cleaned_data
        password = cleaned_data.get('password')
        passwordconfirm = cleaned_data.get('passwordconfirm')
        if password != passwordconfirm and not self['password'].errors:
            raise forms.ValidationError(_("Passwords didn't match"))
        return cleaned_data


# {{workflow}}
class OldNewAccountForm(GenericEmailForm):
    pass


class NewAccountForm(GenericEmailForm, ResetPasswordForm):
    displayname_widget_conf = {
        'class': 'textType',
        'size': '20',
    }

    if get_current_brand() == 'ubuntuone':
        displayname_widget_conf['placeholder'] = _('Your name')

        accept_tos = fields.BooleanField(
            error_messages=tos_error,
            required=True,
            widget=widgets.CheckboxInput(attrs={'required': 'required'}),
        )

    displayname = fields.CharField(
        error_messages=default_errors,
        widget=widgets.TextInput(attrs=displayname_widget_conf),
    )


class ConfirmNewAccountForm(ResetPasswordForm):
    displayname = fields.CharField(
        error_messages=default_errors,
        widget=widgets.TextInput(attrs={'class': 'textType', 'size': '20'}),
    )


class TokenForm(GenericEmailForm):
    """If the confirmation-code and e-mail are entered correctly, and
    if the specified code exists and can be used, the confirmation
    object is placed in cleaned_data['confirmation']."""

    confirmation_code = fields.CharField()

    def clean(self):
        data = self.cleaned_data
        confirmation_code = data.get('confirmation_code')
        email = data.get('email')
        if confirmation_code is not None and email is not None:
            confirmation = verify_token_string(confirmation_code, email)
            if confirmation is None:
                msg = _("Unknown confirmation code.")
                self.errors['confirmation_code'] = [msg]
            data['confirmation'] = confirmation
        return data


class PreferredEmailField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return obj.email


class EditAccountForm(forms.ModelForm):

    displayname = fields.CharField(
        error_messages=default_errors,
        widget=ROAwareTextInput(attrs={'class': 'textType', 'size': '20'}))

    password_widget_conf = {
        'class': 'disableAutoComplete textType',
        'size': '20',
    }

    if get_current_brand() == 'ubuntuone':
        password_widget_conf['placeholder'] = _('8 characters minimum')

    password = fields.CharField(
        required=False,
        help_text=PASSWORD_POLICY_HELP_TEXT,
        validators=[validate_password_policy],
        widget=widgets.PasswordInput(attrs=password_widget_conf),
    )
    passwordconfirm = fields.CharField(
        required=False,
        widget=widgets.PasswordInput(attrs={
            'class': 'disableAutoComplete textType',
            'size': '20',
        }),
    )
    twofactor_required = fields.BooleanField(
        required=False,
        widget=widgets.RadioSelect(
            choices=TWOFACTOR_CHOICES,
        ),
    )
    warn_about_backup_device = fields.BooleanField(
        label=_('Warn me about not having a backup device'),
        required=False)

    def __init__(self, *args, **kwargs):
        self.password_changed = False
        enable_device_prefs = kwargs.pop('enable_device_prefs', False)

        super(EditAccountForm, self).__init__(*args, **kwargs)

        if self.instance.preferredemail is None:
            preferredemail_id = None
        else:
            preferredemail_id = self.instance.preferredemail.id

        # check for emails that can be preferred
        validated_emails = self.instance.verified_emails()

        if validated_emails.count() > 0:

            if get_current_brand() == 'ubuntuone':
                text = _(
                    'Only verified email addresses are listed. '
                    'Click <a href="%s">Manage email addresses</a> '
                    'to add and verify email addresses.') % reverse(
                        'account-emails'
                    )
            else:
                text = _(
                    'Only verified email addresses are listed. '
                    'You can add and verify emails through the link below.')

            # add and display a dropdown with the valid choices
            self.fields['preferred_email'] = PreferredEmailField(
                queryset=validated_emails.order_by('email'),
                initial=preferredemail_id,
                widget=ROAwareSelect,
                error_messages=email_errors,
                empty_label=None,
                help_text=text,
            )

        if not enable_device_prefs:
            self.fields.pop('twofactor_required')
            self.fields.pop('warn_about_backup_device')

    class Meta:
        fields = ('displayname', 'warn_about_backup_device',
                  'twofactor_required')
        model = Account

    def clean_displayname(self):
        name = self.cleaned_data['displayname'].strip()
        if len(name) == 0:
            raise forms.ValidationError(_("Required field"))
        return name

    def clean_preferred_email(self):
        if 'preferred_email' in self.cleaned_data:
            email = self.cleaned_data['preferred_email']
            if email.status == EmailStatus.NEW:
                logger.debug("status is NEW.")
                raise forms.ValidationError(_("Please select an "
                                              "already validated address."))
            return email

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if (not password and
                (self.data.get('currentpassword') or
                 self.data.get('passwordconfirm'))):
            raise forms.ValidationError(_("Required field"))
        return password

    def clean_passwordconfirm(self):
        password = self.cleaned_data.get('passwordconfirm')
        if (not password and
                (self.data.get('currentpassword') or
                 self.data.get('passwordconfirm'))):
            raise forms.ValidationError(_("Required field."))
        return password

    def clean(self):
        cleaned_data = super(EditAccountForm, self).clean()
        password = cleaned_data.get('password')
        passwordconfirm = cleaned_data.get('passwordconfirm')
        if ((password or passwordconfirm) and
                password != passwordconfirm and
                not self['password'].errors and
                not self['passwordconfirm'].errors):
            raise forms.ValidationError(_("Passwords didn't match"))
        return cleaned_data

    def save(self):
        password = self.cleaned_data['password']
        if password:
            self.instance.set_password(password)
            self.password_changed = True
        if 'preferred_email' in self.cleaned_data:
            self.instance.preferredemail = self.cleaned_data['preferred_email']

        super(EditAccountForm, self).save()


class NewEmailForm(forms.Form):

    newemail_widget_conf = {'class': 'textType', 'size': '26'}

    if get_current_brand() == 'ubuntuone':
        newemail_widget_conf['placeholder'] = _('Email address')
        newemail_widget = widgets.Input(attrs=newemail_widget_conf)
        newemail_widget.input_type = 'email'
    else:
        newemail_widget = widgets.TextInput(attrs=newemail_widget_conf)

    newemail = fields.EmailField(
        error_messages=email_errors,
        widget=newemail_widget)

    def __init__(self, *args, **kwargs):
        self.account = kwargs.pop('account', None)
        super(NewEmailForm, self).__init__(*args, **kwargs)

    def clean_newemail(self):
        data = self.cleaned_data['newemail']
        try:
            if self.account is not None:
                # check email was not previously invalidated for this account
                invalidated = self.account.invalidatedemailaddress_set.filter(
                    email__iexact=data)
                if invalidated.exists():
                    raise forms.ValidationError(_(
                        "Email previously invalidated for this account."
                    ))
            email = EmailAddress.objects.get(email__iexact=data)
            if email.status != EmailStatus.NEW:
                raise forms.ValidationError(_(
                    "Email already associated with account."
                ))
        except EmailAddress.DoesNotExist:
            return data
        return data


class PreAuthorizeForm(forms.Form):
    trust_root = forms.CharField(error_messages=default_errors)
    callback = forms.CharField(error_messages=default_errors)


class UserAttribsRequestForm(Form):
    """A form object for user control over OpenID Attribute Exchange."""

    def __init__(self, request, sreg_request, ax_request, rpconfig,
                 approved_data=None):
        self.request = request
        self.sreg_request = sreg_request
        self.ax_request = ax_request
        self.rpconfig = rpconfig
        self.approved_data = approved_data
        # generate initial form data
        self._split_and_filter_requested_attributes()
        self._get_data_for_user()
        super(UserAttribsRequestForm, self).__init__(self.data)
        self._init_fields(self.data)

    def _split_and_filter_requested_attributes(self):
        # Merge the requested attributes from sreg_request and ax_request and
        # filter out any that we don't recognise or that aren't allowed by our
        # rpconfig.
        # The rule is that if at least one request lists it as required, it's
        # required, otherwise it's optional.
        known_attribs = set([a for a in AX_DATA_FIELDS.iterAliases()])
        if self.rpconfig is not None:
            allowed = self.rpconfig.allowed_user_attribs or ''
            allowed_attribs = known_attribs.intersection(allowed.split(','))
        else:
            allowed_attribs = known_attribs

        required = set()
        optional = set()
        if self.sreg_request:
            required.update(self.sreg_request.required)
            optional.update(self.sreg_request.optional)
        if self.ax_request:
            for uri, attr in self.ax_request.requested_attributes.iteritems():
                if attr.required:
                    required.add(AX_DATA_FIELDS.getAlias(uri))
                else:
                    optional.add(AX_DATA_FIELDS.getAlias(uri))
        optional.difference_update(required)
        self.required = required.intersection(allowed_attribs)
        self.optional = optional.intersection(allowed_attribs)

    def _get_data_for_user(self):
        """Get the data to ask about in the form based on the user's
        account record.
        """
        values = {}
        user = self.request.user
        values['fullname'] = user.displayname
        if user.preferredemail is not None:
            values['email'] = user.preferredemail.email
        if user.person is not None:
            values['nickname'] = user.person.name
            if user.person.time_zone is not None:
                values['timezone'] = user.person.time_zone
        if user.preferredlanguage is not None:
            values['language'] = user.preferredlanguage
        else:
            values['language'] = translation.get_language_from_request(
                self.request)
        values['account_verified'] = (
            'token_via_email' if user.is_verified else 'no')
        logger.debug('user attrib values = %s', str(values))

        self.data = dict([(f, values[f]) for f in self.required | self.optional
                          if f in values])

    def _init_fields(self, data):
        """Initialises form fields for the user's ax data.
        """
        for key, val in data.items():
            label = "%s: %s" % (AX_DATA_LABELS.get(key, key), val)
            attrs = {}
            if (key in self.required):
                attrs['class'] = 'required'
                if self.rpconfig is not None:
                    attrs['disabled'] = 'disabled'
            self.fields[key] = fields.BooleanField(
                label=label,
                widget=forms.CheckboxInput(attrs=attrs,
                                           check_test=self.check_test(key)),
            )

    def check_test(self, name):
        """Determines if a checkbox should be pre-checked based on previously
        approved user data, openid request and relying party type.
        """
        def inner(value):
            # Don't approve fields that weren't requested
            if name not in (self.required | self.optional):
                return False

            if self.rpconfig:
                # Trusted site, check required fields
                if (name in self.required):
                    return True
                if self.approved_data and name in self.approved_data.get(
                        'requested', []):
                    # The field was previously requested, use the same response
                    return name in self.approved_data.get('approved', [])
                # We've never (dis)approved this field before, default to True
                return True
            else:
                # If we have previous (dis)approval for this site, use it
                if self.approved_data and name in self.approved_data.get(
                        'requested', []):
                    return name in self.approved_data.get('approved', [])
                # No previous (dis)approval, check required and leave the rest
                return name in self.required
        return inner

    def field_approved(self, field):
        """Check if the field should be returned in the response based on user
        preferences and overridden for trusted relying parties.
        """
        post = self.request.POST
        approved = set([k for k in post.keys() if post[k]])
        if self.rpconfig is not None:
            approved.update(self.required)
            if self.rpconfig.auto_authorize:
                approved.update(self.optional)
        return field in approved

    @property
    def data_approved_for_request(self):
        """Return the list of user attributes approved for the request."""
        return dict(
            [(f, self.data[f]) for f in self.data if self.field_approved(f)])

    @property
    def has_data(self):
        """Helper property to check if this form has any data."""
        return len(self.data) > 0


class TeamsRequestForm(Form):
    """A form object for user control over OpenID teams data.
    """

    fields = {}

    @property
    def teams_approved_by_user(self):
        """Get the list of teams actually approved by the user for the request.
        """
        if self.request_method == 'POST':
            return [t for t in self.memberships if t in self.request.POST]
        else:
            return []

    def __init__(self, request, teams_request, rpconfig, approved_data=None):
        self.request = request
        self.request_method = request.META.get('REQUEST_METHOD')
        self.teams_request = teams_request
        self.rpconfig = rpconfig
        self.approved_data = approved_data
        self.memberships = self._get_teams_for_user(
            request.user, rpconfig and rpconfig.can_query_any_team)

        super(TeamsRequestForm, self).__init__(self.memberships)

        self._init_fields(self.memberships)

    def _get_teams_for_user(self, user, include_private=False):
        """Get the list of teams to ask about in the form based on the user's
        team membership.
        """
        all_teams = self.teams_request.allRequestedTeams()
        memberships = get_team_memberships_for_user(all_teams, user,
                                                    include_private)
        return dict((t, t) for t in memberships)

    def _init_fields(self, form_data):
        """Initialises form fields for the user's team memberships.
        """
        if len(form_data) == 1:
            label_format = 'Team membership: %s'
        else:
            label_format = '%s'
        for team in form_data:
            label = label_format % team
            self.fields[team] = fields.BooleanField(
                label=label, widget=forms.CheckboxInput(
                    check_test=self.check_test(team)))

    def check_test(self, name):
        """Determines if a checkbox should be pre-checked based on previously
        approved user data and relying party type.
        """
        def inner(value):
            if (self.approved_data and
                    name in self.approved_data.get('requested', [])):
                return name in self.approved_data.get('approved', [])
            else:
                return self.rpconfig is not None
        return inner

    @property
    def has_data(self):
        """Helper property to check if this form has any data."""
        return len(self.memberships) > 0


class HOTPDeviceForm(Form):
    name = fields.CharField()
    otp = OATHPasswordField()


class DeviceRenameForm(Form):
    name = fields.CharField()

    def clean_name(self):
        data = self.cleaned_data['name'].strip()
        if data != '':
            return data

        raise forms.ValidationError(
            _('The name must contain at least one non-whitespace character.'))
