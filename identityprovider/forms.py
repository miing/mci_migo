# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import logging

from django import forms
from django.conf import settings
from django.forms import Form, fields, widgets
from django.utils import translation
from django.utils.translation import ugettext as _

from identityprovider.const import (
    SREG_DATA_FIELDS_ORDER,
    SREG_LABELS,
)
from identityprovider.models import (
    Account,
    EmailAddress,
    verify_token_string,
    get_team_memberships_for_user,
)
from identityprovider.models.const import EmailStatus
from identityprovider.utils import (
    encrypt_launchpad_password,
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


class GenericEmailForm(forms.Form):
    email_widget_conf = {'class': 'textType', 'size': '26'}

    # add placeholder, autofocus and email type for the u1 brand
    if settings.BRAND == 'ubuntuone':
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

    if settings.BRAND == 'ubuntuone':
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

    if settings.BRAND == 'ubuntuone':
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

    if settings.BRAND == 'ubuntuone':
        displayname_widget_conf['placeholder'] = _('Your name')

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
    password = fields.CharField(
        required=False,
        help_text=PASSWORD_POLICY_HELP_TEXT,
        validators=[validate_password_policy],
        widget=widgets.PasswordInput(attrs={
            'class': 'disableAutoComplete textType',
            'size': '20',
        }),
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
        enable_device_prefs = kwargs.pop('enable_device_prefs', False)

        super(EditAccountForm, self).__init__(*args, **kwargs)

        if self.instance.preferredemail is None:
            preferredemail_id = None
        else:
            preferredemail_id = self.instance.preferredemail.id

        # check for emails that can be preferred
        validated_emails = self.instance.verified_emails()

        if validated_emails.count() > 0:
            # add and display a dropdown with the valid choices
            self.fields['preferred_email'] = PreferredEmailField(
                queryset=validated_emails.order_by('email'),
                initial=preferredemail_id,
                widget=ROAwareSelect,
                error_messages=email_errors,
                empty_label=None,
                help_text=_(
                    'Only verified email addresses are listed. '
                    'You can add and verify emails through the link below.'),
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
            new_password = encrypt_launchpad_password(password)
            self.instance.accountpassword.password = new_password
            self.instance.accountpassword.save()
        if 'preferred_email' in self.cleaned_data:
            self.instance.preferredemail = self.cleaned_data['preferred_email']

        super(EditAccountForm, self).save()


class NewEmailForm(forms.Form):
    newemail = fields.EmailField(
        error_messages=email_errors,
        widget=widgets.TextInput(attrs={'class': 'textType', 'size': '26'}))

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


class SRegRequestForm(Form):
    """A form object for user control over OpenID sreg data.
    """
    fields = {}

    @property
    def data_approved_for_request(self):
        """Return the list of sreg data approved for the request."""
        return dict([(f, self.data[f]) for f in self.data
                     if self.field_approved(f)])

    def __init__(self, request, sreg_request, rpconfig, approved_data=None):
        self.request = request
        self.request_method = request.META.get('REQUEST_METHOD')
        self.sreg_request = sreg_request
        self.rpconfig = rpconfig
        self.approved_data = approved_data
        # generate initial form data
        sreg_fields = [f for f in SREG_DATA_FIELDS_ORDER if f in set(
            self.sreg_request.required + self.sreg_request.optional)]
        if rpconfig is not None:
            if rpconfig.allowed_sreg:
                fields = set(sreg_fields).intersection(
                    set(rpconfig.allowed_sreg.split(',')))
            else:
                fields = set()
        else:
            fields = sreg_fields
        self.data = self._get_sreg_data_for_user(request.user, fields)

        super(SRegRequestForm, self).__init__(self.data)
        self._init_fields(self.data)
        self.should_display = len(self.data) > 0

    def _get_sreg_data_for_user(self, user, sreg_fields):
        """Get the sreg data to ask about in the form based on the user's
        account record.
        """
        values = {}
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
        logger.debug("values (sreg_fields) = " + str(values))

        return dict([(f, values[f]) for f in sreg_fields if f in values])

    def _init_fields(self, data):
        """Initialises form fields for the user's sreg data.
        """
        for key, val in data.items():
            label = "%s: %s" % (SREG_LABELS.get(key, key), val)
            attrs = {}
            if key in self.sreg_request.required:
                attrs['class'] = 'required'
                if self.rpconfig is not None:
                    attrs['disabled'] = 'disabled'
            self.fields[key] = fields.BooleanField(
                label=label,
                widget=forms.CheckboxInput(attrs=attrs,
                                           check_test=self.check_test),
            )

    def check_test(self, value):
        """Determines if a checkbox should be pre-checked based on previously
        approved user data, openid request and relying party type.
        """
        for k, v in self.data.items():
            if value == v:
                value = k
                break

        if self.rpconfig and value in self.sreg_request.required:
            return True
        elif (self.approved_data and
                value in self.approved_data.get('requested', [])):
            return value in self.approved_data.get('approved', [])
        elif self.rpconfig:
            return True
        else:
            return value in self.sreg_request.required

    def field_approved(self, field):
        """Check if the field should be returned in the response based on user
        preferences and overridden for trusted relying parties.
        """
        approved = set(self.request.POST.keys())
        if self.rpconfig is not None:
            sreg_fields = set(self.sreg_request.required)
            if self.rpconfig.auto_authorize:
                # also include optional fields
                sreg_fields.update(set(self.sreg_request.optional))
            approved.update(sreg_fields)
        return field in approved


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
        self.should_display = len(self.memberships) > 0

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
        for team in form_data:
            self.fields[team] = fields.BooleanField(
                label=team, widget=forms.CheckboxInput(
                    check_test=self.check_test))

    def check_test(self, value):
        """Determines if a checkbox should be pre-checked based on previously
        approved user data and relying party type.
        """
        if (self.approved_data and
                value in self.approved_data.get('requested', [])):
            return value in self.approved_data.get('approved', [])
        else:
            return self.rpconfig is not None


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
