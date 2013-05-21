# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django import forms
from django.contrib import admin
from django.core.urlresolvers import reverse
from django.template.defaultfilters import force_escape

from identityprovider.const import (
    AX_DATA_LABELS,
    SREG_LABELS,
)
from identityprovider.fields import CommaSeparatedField
from identityprovider.models import (
    Account,
    AccountPassword,
    APIUser,
    AuthenticationDevice,
    AuthToken,
    EmailAddress,
    InvalidatedEmailAddress,
    OpenIDRPConfig,
)
from identityprovider.models.const import AccountStatus, EmailStatus
from identityprovider.utils import encrypt_launchpad_password
from identityprovider.widgets import (
    CommaSeparatedWidget,
    LPUsernameWidget,
    ReadOnlyDateTimeWidget,
    StatusWidget,
    account_to_lp_link,
)


DEVICE_TYPE_CHOICES = [
    (None, 'Unset'),
    ('paper', 'Printable backup codes'),
    ('yubi', 'YubiKey'),
    ('google', 'Smartphone or tablet'),
    ('generic', 'Generic HOTP device')
]


class OpenIDRPConfigForm(forms.ModelForm):
    displayname = forms.CharField(label="Display name")
    trust_root = forms.URLField()
    logo = forms.CharField(required=False)
    allowed_user_attribs = CommaSeparatedField(
        choices=AX_DATA_LABELS.items(),
        required=False,
        widget=CommaSeparatedWidget,
    )
    allowed_ax = CommaSeparatedField(
        choices=AX_DATA_LABELS.items(),
        required=False,
        widget=CommaSeparatedWidget,
    )
    allowed_sreg = CommaSeparatedField(
        choices=SREG_LABELS.items(),
        required=False,
        widget=CommaSeparatedWidget
    )
    can_query_any_team = forms.BooleanField(label="Can query private teams",
                                            required=False)
    auto_authorize = forms.BooleanField(label="Auto-authorize",
                                        required=False)
    allow_unverified = forms.BooleanField(label="Allow unverified accounts",
                                          required=False)


class OpenIDRPConfigAdmin(admin.ModelAdmin):
    class Media:
        css = {
            'all': ("/assets/identityprovider/admin-fixes.css",)
        }

    form = OpenIDRPConfigForm
    list_display = ('displayname', 'trust_root', 'can_query_any_team',
                    'auto_authorize', 'require_two_factor')
    list_display_links = ('displayname', 'trust_root')
    list_editable = ('require_two_factor',)
    list_filter = ('require_two_factor',)
    ordering = ('displayname',)
    search_fields = ('displayname', 'trust_root')


class AccountPasswordInlineForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput, required=False,
        label="Password",
        help_text="Enter the new password in plain text, it will "
                  "be properly encrypted into the database.")

    class Meta:
        model = AccountPassword

    def __init__(self, *args, **kwargs):
        initial = kwargs.get('initial', {})
        initial.update({'password': ''})
        kwargs['initial'] = initial
        super(AccountPasswordInlineForm, self).__init__(*args, **kwargs)


class AccountPasswordFormset(forms.models.BaseInlineFormSet):
    def __init__(self, *args, **kwargs):
        super(AccountPasswordFormset, self).__init__(*args, **kwargs)
        self.can_delete = False


class AccountPasswordInline(admin.StackedInline):
    model = AccountPassword
    form = AccountPasswordInlineForm
    formset = AccountPasswordFormset


class AuthenticationDeviceInlineForm(forms.ModelForm):
    class Meta:
        model = AuthenticationDevice
        exclude = ('account',)

    key = forms.CharField(widget=forms.TextInput(attrs={'size': 40}),
                          label="OATH/HOTP key")
    name = forms.CharField(widget=forms.TextInput(attrs={'size': 15}),
                           label="Device name")
    device_type = forms.ChoiceField(choices=DEVICE_TYPE_CHOICES,
                                    label="Device type")


class AuthenticationDeviceInline(admin.TabularInline):
    model = AuthenticationDevice
    form = AuthenticationDeviceInlineForm
    extra = 0


class EmailAddressInlineForm(forms.ModelForm):
    class Meta:
        model = EmailAddress

    email = forms.CharField(widget=forms.TextInput(attrs={'size': 40}),
                            label="Email address")


class EmailAddressInlineFormSet(forms.models.BaseInlineFormSet):

    def clean(self):
        super(EmailAddressInlineFormSet, self).clean()
        count = 0
        for form in self.forms:
            if form.is_valid() and form.cleaned_data:
                status = form.cleaned_data['status']
                if status == EmailStatus.PREFERRED:
                    count += 1
        if count > 1:
            raise forms.ValidationError(
                "Only one email address can be preferred.")


class EmailAddressInline(admin.TabularInline):
    model = EmailAddress
    form = EmailAddressInlineForm
    formset = EmailAddressInlineFormSet
    verbose_name_plural = "Email addresses"


class LPUsernameField(forms.Field):
    widget = LPUsernameWidget


class AccountAdminForm(forms.ModelForm):
    class Meta:
        model = Account
        exclude = ('date_status_set',)

    def __init__(self, *args, **kwargs):
        instance = kwargs.get('instance')
        if instance:
            widget = self.declared_fields['status'].widget
            widget.date_status_set = instance.date_status_set

            widget = self.declared_fields['date_created'].widget
            widget.value = instance.date_created

            widget = self.declared_fields['lp_username'].widget
            widget.account = instance
        super(AccountAdminForm, self).__init__(*args, **kwargs)

    date_created = forms.DateTimeField(widget=ReadOnlyDateTimeWidget,
                                       required=False)
    lp_username = LPUsernameField(label="LP username", required=False)
    status = forms.TypedChoiceField(widget=StatusWidget, coerce=int,
                                    choices=AccountStatus._get_choices())

    displayname = forms.CharField(label="Display name",
                                  widget=forms.TextInput)
    openid_identifier = forms.CharField(label="OpenID identifier",
                                        widget=forms.TextInput)


class AccountAdmin(admin.ModelAdmin):
    inlines = [AccountPasswordInline, EmailAddressInline,
               AuthenticationDeviceInline]

    form = AccountAdminForm

    def preferred_email(self, account):
        return account.preferredemail or ''

    def name(self, account):
        return account_to_lp_link(account)

    name.short_description = "LP username"
    name.allow_tags = True

    def save_formset(self, request, form, formset, change):
        if formset.model is AccountPassword:
            password = formset.forms[0].cleaned_data.get('password')
            instances = formset.save(commit=False)
            if len(instances) == 1 and password:
                instance = instances[0]
                encrypted_password = encrypt_launchpad_password(password)
                instance.password = encrypted_password
                instance.save()
        else:
            super(AccountAdmin, self).save_formset(
                request, form, formset, change)

    fieldsets = (
        (None, {
            'fields': ('date_created', 'lp_username', 'creation_rationale',
                       'status', 'displayname', 'openid_identifier',
                       'twofactor_required', 'warn_about_backup_device')
        }),
    )

    list_display = ('__unicode__', 'preferred_email', 'name', 'status')
    search_fields = ('displayname', '=openid_identifier')
    list_filter = ('date_created', 'status', 'date_status_set')


class APIUserAdminForm(forms.ModelForm):
    class Meta:
        model = APIUser

    def __init__(self, *args, **kwargs):
        kwargs['initial'] = {'password': ''}
        super(APIUserAdminForm, self).__init__(*args, **kwargs)

    password = forms.CharField(required=False)


class APIUserAdmin(admin.ModelAdmin):
    model = APIUser

    form = APIUserAdminForm

    search_fields = ['username']

    def save_model(self, request, obj, form, change):
        password = form.cleaned_data.get('password')
        if password:
            obj.set_password(password)
        obj.save()


class EmailAddressForm(forms.ModelForm):
    email = forms.CharField(widget=forms.TextInput(attrs={'size': 40}),
                            label="Email address")

    class Meta:
        model = EmailAddress


class EmailAddressAdmin(admin.ModelAdmin):
    form = EmailAddressForm
    model = EmailAddress
    raw_id_fields = ('account',)
    list_display = ('email', 'status', 'account_link')
    search_fields = ('=email',)

    def account_link(self, obj):
        if obj.account is None:
            return "None"

        url = reverse(
            'admin:identityprovider_account_change', args=(obj.account.id,))
        snippet = '<a href="%s">%s</a>'
        info = (url, force_escape(obj.account.displayname))
        return snippet % info
    account_link.allow_tags = True


class InvalidatedEmailAddressForm(forms.ModelForm):
    email = forms.CharField(widget=forms.TextInput(attrs={'size': 40}),
                            label="Email address")

    class Meta:
        model = InvalidatedEmailAddress


class InvalidatedEmailAddressAdmin(EmailAddressAdmin):
    form = InvalidatedEmailAddressForm
    model = InvalidatedEmailAddress
    list_display = ('email', 'account_link')


admin.site.register(AuthToken)
admin.site.register(Account, AccountAdmin)
admin.site.register(OpenIDRPConfig, OpenIDRPConfigAdmin)
admin.site.register(APIUser, APIUserAdmin)
admin.site.register(EmailAddress, EmailAddressAdmin)
admin.site.register(InvalidatedEmailAddress, InvalidatedEmailAddressAdmin)
