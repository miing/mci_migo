# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

# We use Django forms for webservice input validation

from django import forms
from django.forms import fields
from django.utils.translation import ugettext as _

from identityprovider.models.captcha import Captcha
from identityprovider.validators import validate_password_policy


class WebserviceCreateAccountForm(forms.Form):
    email = fields.EmailField()
    password = fields.CharField(max_length=256,
                                validators=[validate_password_policy])
    captcha_id = fields.CharField(max_length=1024)
    captcha_solution = fields.CharField(max_length=256)
    remote_ip = fields.CharField(max_length=256)
    displayname = fields.CharField(max_length=256, required=False)
    platform = fields.TypedChoiceField(choices=[
        ('web', 'Web'), ('desktop', 'Desktop'), ('mobile', 'Mobile')],
        empty_value='desktop', required=False)
    validate_redirect_to = fields.CharField(required=False)

    def clean_validate_redirect_to(self):
        validate_redirect_to = self.cleaned_data.get('validate_redirect_to')
        # return None instead of '' as the default value
        if not validate_redirect_to:
            validate_redirect_to = None
        return validate_redirect_to

    def clean(self):
        cleaned_data = self.cleaned_data
        captcha_id = cleaned_data.get('captcha_id')
        captcha_solution = cleaned_data.get('captcha_solution')

        # The remote IP address is absolutely required, and comes from
        # SSO itself, not from the client.  If it's missing, it's a
        # programming error, and should not be returned to the client
        # as a validation error.  So, we use a normal key lookup here.
        remote_ip = cleaned_data['remote_ip']

        captcha = Captcha(captcha_id)
        email = cleaned_data.get('email', '')
        if captcha.verify(captcha_solution, remote_ip, email):
            return cleaned_data
        # not verified
        raise forms.ValidationError(_("Wrong captcha solution."))
