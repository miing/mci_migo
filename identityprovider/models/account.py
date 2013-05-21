# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

import logging

from datetime import date, datetime, timedelta

from django.conf import settings
from django.contrib.auth import get_backends
from django.contrib.auth.models import User, update_last_login
from django.contrib.auth.signals import user_logged_in
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from model_utils.managers import PassThroughManager
from oauth_backend.models import Consumer, Token
from south.modelsinspector import add_introspection_rules

from gargoyle import gargoyle

from identityprovider.models.const import (
    AccountCreationRationale,
    AccountStatus,
    EmailStatus,
)
from identityprovider.utils import (
    encrypt_launchpad_password,
    generate_openid_identifier,
    get_object_or_none,
)

from identityprovider.validators import (
    Errors,
    validate_password_policy,
)

__all__ = [
    'Account',
    'AccountPassword',
    'DisplaynameField',
    'PasswordField',
    'LPOpenIdIdentifier',
]

# Disconnect default signal handler, which tries to update last_login
# field on the db level, but on the Account object this is a virtual
# property
user_logged_in.disconnect(update_last_login)


def update_account_last_login(**kwargs):
    account = kwargs['user']
    account.last_login = timezone.now()
    # there's no ned to save, as property handler does that

user_logged_in.connect(update_account_last_login)


class AccountQuerySet(models.query.QuerySet):
    def verified(self):
        return self.filter(
            emailaddress__status__in=(EmailStatus.VALIDATED,
                                      EmailStatus.PREFERRED)).distinct()


class AccountManager(PassThroughManager):
    """Extend the default manager.

    Add a method that takes care of creating an Account, and the necessary
    AccountPassword, EmailAddress objects.

    """

    def create_account(self, displayname, email_address, password,
                       creation_rationale=None, salt=None,
                       password_encrypted=False, email_validated=True,
                       openid_identifier=None):
        from identityprovider.models import EmailAddress

        errors = Errors()
        # do validation before account (and related) creation/save
        if not password_encrypted:
            # an encrypted password is assumed to be valid
            # this will raise a ValidationError if password does not
            # complies with policy
            with errors.collect('password'):
                validate_password_policy(password)
                password = encrypt_launchpad_password(password, salt=salt)

        email_status = (
            EmailStatus.PREFERRED if email_validated else EmailStatus.NEW)
        email = EmailAddress(email=email_address, status=email_status)

        with errors.collect('email'):
            email.full_clean()

        if errors:
            raise ValidationError(errors)

        if creation_rationale is None:
            creation_rationale = (
                AccountCreationRationale.OWNER_CREATED_LAUNCHPAD)

        kwargs = {
            'displayname': displayname,
            'creation_rationale': creation_rationale,
            'status': AccountStatus.ACTIVE,
        }

        if openid_identifier is not None:
            kwargs['openid_identifier'] = openid_identifier

        account = Account.objects.create(**kwargs)
        email.account = account
        email.save()
        password = AccountPassword.objects.create(
            account=account,
            password=password)
        return account

    def get_by_email(self, email):
        return get_object_or_none(self.select_related(),
                                  emailaddress__email__iexact=email)

    def active_by_openid(self, openid_identifier):
        return get_object_or_none(self, openid_identifier=openid_identifier,
                                  status=AccountStatus.ACTIVE)


class DisplaynameField(models.TextField):
    def __init__(self, null=False, **kwargs):
        super(DisplaynameField, self).__init__(null=null, **kwargs)


class PasswordField(models.TextField):
    def __init__(self, null=False, **kwargs):
        super(PasswordField, self).__init__(null=null, **kwargs)


class Account(models.Model):
    date_created = models.DateTimeField(default=datetime.utcnow,
                                        editable=False)
    creation_rationale = models.IntegerField(
        choices=AccountCreationRationale._get_choices())
    status = models.IntegerField(choices=AccountStatus._get_choices())
    date_status_set = models.DateTimeField(default=datetime.utcnow)
    displayname = DisplaynameField()
    openid_identifier = models.TextField(default=generate_openid_identifier,
                                         unique=True)
    status_comment = models.TextField(blank=True, null=True)
    old_openid_identifier = models.TextField(blank=True, null=True,
                                             db_index=True)
    preferredlanguage = models.TextField(blank=True, null=True)
    twofactor_required = models.BooleanField(default=False)
    twofactor_attempts = models.SmallIntegerField(default=0, null=True)
    warn_about_backup_device = models.BooleanField(default=True)

    objects = AccountManager.for_queryset_class(AccountQuerySet)()

    class Meta:
        app_label = 'identityprovider'
        db_table = u'account'
        verbose_name = _('account')
        verbose_name_plural = _('accounts')

    def __unicode__(self):
        return self.displayname

    @property
    def openid_identity_url(self):
        server = settings.SSO_ROOT_URL.rstrip('/')
        return '%s/+id/%s' % (server, self.openid_identifier)

    @property
    def need_backup_device_warning(self):
        return self.warn_about_backup_device and self.devices.count() == 1

    @property
    def paper_devices_needing_renewal(self):
        devices = self.devices.filter(device_type='paper')
        size = settings.TWOFACTOR_PAPER_CODES
        for device in devices:
            used = device.counter % size
            if used > (size - settings.TWOFACTOR_PAPER_CODES_WARN_RENEWAL):
                yield device

    @property
    def is_verified(self):
        return self.verified_emails().count() > 0

    def verified_emails(self):
        """Returns all verified e-mail addresses (including
        preferred), with preferred sort first."""
        email = self.emailaddress_set.verified()
        return email.order_by('-status', 'email')

    def unverified_emails(self):
        email = self.emailaddress_set.filter(status=EmailStatus.NEW)
        return email.order_by('email')

    def last_authenticated_sites(self, limit=10):
        sites = self.openidrpsummary_set.order_by('-date_last_used')
        return sites if limit is None else sites[:limit]

    def sites_with_active_sessions(self, age_hours=24):
        """
        Return list of sites on which user *may* have active sessions

        Current rule of thumb is to return all sites accessed within previous
        24 hours.
        """
        max_date_last_used = (datetime.utcnow() -
                              timedelta(hours=age_hours))
        sites = self.openidrpsummary_set.filter(
            date_last_used__gte=max_date_last_used)
        return sites.order_by('-date_last_used')

    def _get_preferredemail(self):
        if not hasattr(self, '_preferredemail'):
            try:
                email = None
                account_emails = self.emailaddress_set.filter(
                    status=EmailStatus.PREFERRED)
                if account_emails.count() > 0:
                    email = account_emails[0]

                if not email:
                    # Try to determine a suitable address, and mark it
                    # as preferred.
                    emails = self.emailaddress_set.filter(
                        status=EmailStatus.VALIDATED)
                    if emails.count() > 0:
                        email = emails.order_by('date_created')[0]
                        email.status = EmailStatus.PREFERRED
                        email.save()
                        logging.info(
                            "Updating preferred email for account %s"
                            % self.id
                        )

                if not email and gargoyle.is_active('ALLOW_UNVERIFIED',
                                                    self):
                    # we have no validated email, so use the first NEW email
                    # but don't save it
                    emails = self.emailaddress_set.filter(
                        status=EmailStatus.NEW)
                    if emails.count() > 0:
                        email = emails.order_by('date_created')[0]

                self._preferredemail = email
            except:
                # no error in preffered email should raise, as this breaks
                # login completely
                self._preferredemail = None
        return self._preferredemail

    def _set_preferredemail(self, email):
        if not email.is_verified:
            raise ValidationError('Email must be verified')
        current = self.preferredemail
        if current is not None:
            current.status = EmailStatus.VALIDATED
            current.save()
            if current != email:
                # avoid circular import
                from identityprovider import emailutils
                emailutils.send_preferred_changed_notification(
                    current.email, email.email)
        email.status = EmailStatus.PREFERRED
        email.save()
        self._preferredemail = email

    preferredemail = property(_get_preferredemail, _set_preferredemail)

    @property
    def person(self):
        if not hasattr(self, '_person'):
            open_ids = LPOpenIdIdentifier.objects.filter(
                identifier=self.openid_identifier)
            if len(open_ids) > 0:
                # Look up Person object with the same lp_account id as it's in
                # lp_OpenIdIdentifier table
                lp_account = open_ids[0].lp_account
                # Importing it here to prevent cyclic import issue
                from .person import Person
                try:
                    self._person = Person.objects.select_related(
                        'personlocation').get(lp_account=lp_account)
                except Person.DoesNotExist:
                    pass
        return getattr(self, '_person', None)

    @property
    def user(self):
        if not hasattr(self, '_user'):
            # When in read only mode we don't want to create users so we'll
            # return what is or None if not there
            if settings.READ_ONLY_MODE:
                self._user = get_object_or_none(
                    User, username=self.openid_identifier)
            else:
                if self.preferredemail:
                    self._user, _ = User.objects.get_or_create(
                        username=self.openid_identifier,
                        defaults={'email': self.preferredemail})
                else:
                    return None

        return self._user

    def _get_last_login(self):
        if self.user is not None:
            return self.user.last_login

    def _set_last_login(self, login_datetime):
        # we can live without last_login
        if settings.READ_ONLY_MODE:
            return

        if self.user is not None:
            self.user.last_login = login_datetime
            self.user.save()

    last_login = property(_get_last_login, _set_last_login)

    @property
    def can_reactivate(self):
        return (self.status == AccountStatus.DEACTIVATED or
                self.status == AccountStatus.NOACCOUNT)

    @property
    def can_reset_password(self):
        return (self.is_active or self.can_reactivate)

    @property
    def is_active(self):
        return (self.status == AccountStatus.ACTIVE)

    def is_authenticated(self):
        return True

    def person_in_team(self, team):
        return self.person is not None and self.person.in_team(team)

    @property
    def is_staff(self):
        # Logging into the admin system with this breaks things
        return False

    @property
    def is_superuser(self):
        return False

    @property
    def first_name(self):
        sname = self.displayname.split(' ')
        return sname[0]

    @property
    def encrypted_password(self):
        try:
            accountpassword = self.accountpassword
            password = accountpassword.password
        except AccountPassword.DoesNotExist:
            password = None
        return password

    def set_password(self, password, salt=None):
        try:
            accountpassword = self.accountpassword
        except AccountPassword.DoesNotExist:
            accountpassword = AccountPassword(account=self, password='invalid')
        accountpassword.password = encrypt_launchpad_password(
            password, salt=salt)
        accountpassword.save()

    def get_and_delete_messages(self):
        return []

    def get_full_name(self):
        return self.displayname

    def has_module_perms(self, app_label):
        if not self.is_active:
            return False
        for backend in get_backends():
            if hasattr(backend, "has_module_perms"):
                if backend.has_module_perms(self, app_label):
                    return True
        return False

    def has_perm(self, perm):
        if not self.is_active:
            return False
        for backend in get_backends():
            if hasattr(backend, "has_perm"):
                if backend.has_perm(self, perm):
                    return True
        return False

    def create_oauth_token(self, token_name):
        user, _ = User.objects.get_or_create(username=self.openid_identifier)
        try:
            consumer = user.oauth_consumer
        except Consumer.DoesNotExist:
            consumer = Consumer.objects.create(user=user)
        token = consumer.token_set.create(name=token_name)
        return token

    def get_or_create_oauth_token(self, token_name):
        user, _ = User.objects.get_or_create(username=self.openid_identifier)
        try:
            consumer = user.oauth_consumer
        except Consumer.DoesNotExist:
            consumer = Consumer.objects.create(user=user)

        tokens = consumer.token_set.filter(name=token_name).order_by(
            '-created_at')
        if tokens:
            # if multiple tokens are present, keep the newest one
            token = tokens[0]
            token.updated_at = datetime.utcnow()
            token.save()
            created = False
        else:
            token = consumer.token_set.create(name=token_name)
            created = True
        return token, created

    def oauth_tokens(self):
        user, _ = User.objects.get_or_create(username=self.openid_identifier)
        try:
            consumer = user.oauth_consumer
            return consumer.token_set.all()
        except Consumer.DoesNotExist:
            return Token.objects.none()

    def invalidate_oauth_tokens(self):
        self.oauth_tokens().delete()

    def has_twofactor_devices(self):
        """Returns True if this Account has any associated two-factor
        devices (including one-time pads)."""
        # TODO: Test for one-time pads.
        return self.devices.exists()

    def suspend(self):
        self.status = AccountStatus.SUSPENDED
        self.save()

    def save(self, force_insert=False, force_update=False, **kwargs):
        if settings.READ_ONLY_MODE:
            return

        # if we suspend the account, reset the password too, to force the user
        # to reset it after the account is re-enabled
        if self.status == AccountStatus.SUSPENDED:
            try:
                # by setting a plain text value we make sure its not going to
                # match against anything
                self.accountpassword.password = 'invalid'
                self.accountpassword.save()
            except AccountPassword.DoesNotExist:
                # no password, so nothing to reset
                pass

        # update date_status_set only when the status value changes
        try:
            old_status = Account.objects.get(id=self.id).status
            if self.status != old_status:
                # update date_status_set
                self.date_status_set = datetime.utcnow()
        except Account.DoesNotExist:
            pass

        # now go and effectively save it
        super(Account, self).save(force_insert, force_update, **kwargs)


class AccountPassword(models.Model):
    account = models.OneToOneField(Account, db_column='account')
    password = PasswordField()

    class Meta:
        app_label = 'identityprovider'
        db_table = u'accountpassword'
        verbose_name = _('account password')
        verbose_name_plural = _('account passwords')

    def __unicode__(self):
        return _("Password for %s") % unicode(self.account)


class LPOpenIdIdentifier(models.Model):
    """
    Mapping between Launchpad accounts and OpenID identifiers
    """
    identifier = models.TextField(unique=True, primary_key=True)
    lp_account = models.IntegerField(null=False, db_column='account',
                                     db_index=True)
    date_created = models.DateTimeField(null=False, default=date.today)

    class Meta:
        app_label = 'identityprovider'
        db_table = u'lp_openididentifier'
        verbose_name = _("LP OpenID Identifier")
        verbose_name_plural = _("LP OpenID Identifiers")

    def __unicode__(self):
        return _("LP OpenID Identifier for %s") % unicode(self.lp_account)


add_introspection_rules(
    [], ["^identityprovider\.models\.account\.PasswordField"])
add_introspection_rules(
    [], ["^identityprovider\.models\.account\.DisplaynameField"])
