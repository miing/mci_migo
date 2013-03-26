# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

import logging
import re

from datetime import datetime

from django.core.validators import validate_email
from django.db import models
from django.utils.translation import ugettext_lazy as _
from model_utils.managers import PassThroughManager

from identityprovider.models import Account, Person
from identityprovider.models.const import EmailStatus

__all__ = (
    'EmailAddress', 'InvalidatedEmailAddress',
)


PHONE_EMAIL_DOMAIN = 'phone.ubuntu'
PHONE_EMAIL_INVALID_CHARS = re.compile(r"[^-!#$%&'*+/=?^_`{}|~0-9A-Z\.]",
                                       re.IGNORECASE)


class EmailAddressQuerySet(models.query.QuerySet):
    def verified(self):
        return self.filter(
            status__in=(EmailStatus.VALIDATED, EmailStatus.PREFERRED))


class EmailAddressManager(PassThroughManager):

    def _generate_email_from_phone_id(self, phone_id):
        # replace chars not validated by django validate_email by #
        email = '%s@%s' % (PHONE_EMAIL_INVALID_CHARS.sub('#', phone_id),
                           PHONE_EMAIL_DOMAIN)
        return email

    def create_from_phone_id(self, phone_id, account):
        email = self._generate_email_from_phone_id(phone_id)
        email_address = EmailAddress.objects.create(
            email=email, account=account, status=EmailStatus.NEW)
        return email_address

    def get_from_phone_id(self, phone_id):
        email = self._generate_email_from_phone_id(phone_id)
        email_address = self.get(email=email)
        return email_address


class EmailAddress(models.Model):
    email = models.TextField(validators=[validate_email])
    lp_person = models.IntegerField(
        db_column='person', blank=True, null=True, editable=False)
    status = models.IntegerField(choices=EmailStatus._get_choices())
    date_created = models.DateTimeField(
        default=datetime.utcnow, blank=True, editable=False)
    account = models.ForeignKey(
        Account, db_column='account', blank=True, null=True)

    objects = EmailAddressManager.for_queryset_class(EmailAddressQuerySet)()

    class Meta:
        app_label = 'identityprovider'
        db_table = u'emailaddress'
        verbose_name_plural = _('Email addresses')

    def __unicode__(self):
        return self.email

    @property
    def is_preferred(self):
        return self.status == EmailStatus.PREFERRED

    @property
    def is_verifiable(self):
        suffix = '@%s' % PHONE_EMAIL_DOMAIN
        return not self.email.endswith(suffix)

    @property
    def is_verified(self):
        return self.status in (EmailStatus.VALIDATED, EmailStatus.PREFERRED)

    def invalidate(self):
        account = self.account
        if account is None and self.lp_person:
            try:
                person = Person.objects.get(id=self.lp_person)
                account = person.account
            except Person.DoesNotExist:
                pass

        invalidated_email = None
        if account:
            # create invalidated entry
            invalidated_email = InvalidatedEmailAddress.objects.create(
                email=self.email, account=account,
                date_created=self.date_created)
        else:
            logging.warning(
                "Could not create invalidated entry for %s, "
                "no associated account found" % self.email)
        # and delete from emails table
        self.delete()
        return invalidated_email


class InvalidatedEmailAddress(models.Model):
    email = models.TextField(validators=[validate_email])
    date_created = models.DateTimeField(blank=True, editable=False)
    date_invalidated = models.DateTimeField(
        default=datetime.utcnow, null=True, blank=True)
    account = models.ForeignKey(
        Account, db_column='account', blank=True, null=True)
    account_notified = models.BooleanField()

    class Meta:
        app_label = 'identityprovider'
        db_table = u'invalidated_emailaddress'
        verbose_name_plural = _('Invalidated email addresses')

    def __unicode__(self):
        return self.email
