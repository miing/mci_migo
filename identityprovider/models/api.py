# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.db import models
from django.utils.translation import ugettext_lazy as _

from identityprovider.utils import (encrypt_launchpad_password,
                                    validate_launchpad_password)


class APIUser(models.Model):
    username = models.CharField(max_length=256)
    password = models.CharField(max_length=256, editable=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def set_password(self, password, salt=None):
        self.password = encrypt_launchpad_password(password, salt=salt)

    def verify_password(self, password):
        return validate_launchpad_password(password, self.password)

    @classmethod
    def authenticate(cls, username, password):
        try:
            api_user = cls.objects.get(username=username)
            if api_user.verify_password(password):
                return api_user
        except cls.DoesNotExist:
            pass
        return None

    def is_authenticated(self):
        # behave like django.contrib.auth.models.User
        return True

    class Meta:
        app_label = "identityprovider"
        db_table = "api_user"
        verbose_name = _('API user')
        verbose_name_plural = _('API users')

    def __unicode__(self):
        return self.username
