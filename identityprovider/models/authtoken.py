# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import datetime
import logging
import random

from urlparse import urljoin

from django.conf import settings
from django.core.urlresolvers import reverse
from django.core.validators import validate_email
from django.db import models

from identityprovider.models import (
    Account,
    DisplaynameField,
    PasswordField,
)
from identityprovider.models.const import TokenType

__all__ = (
    'AUTHTOKEN_LENGTH',
    'AUTHTOKEN_PATTERN',
    'AuthToken',
    'get_type_of_token',
    'verify_token_string'
)


AUTHTOKEN_LENGTH = 6

# For now, we have some older tokens (20 chars) still active, while we
# introduce the shorter tokens.  After a while, we could probably
# bound this pattern's repetition more tightly.
#AUTHTOKEN_PATTERN = '[A-Za-z0-9]{%s}' % AUTHTOKEN_LENGTH
AUTHTOKEN_PATTERN = '[A-Za-z0-9]+'  # % AUTHTOKEN_LENGTH

logger = logging.getLogger(__name__)

urls_mapping = {
    TokenType.INVALIDATEEMAIL: 'invalidate_email',
    TokenType.NEWPERSONLESSACCOUNT: 'confirm_account',
    TokenType.VALIDATEEMAIL: 'confirm_email',
    TokenType.PASSWORDRECOVERY: 'reset_password',
}


class AuthTokenManager(models.Manager):

    valid_types = [
        TokenType.INVALIDATEEMAIL,
        TokenType.NEWPERSONLESSACCOUNT,
        TokenType.VALIDATEEMAIL,
        TokenType.PASSWORDRECOVERY,
    ]

    def create(self, **kwargs):
        token_type = kwargs.get('token_type', -1)
        if token_type not in self.valid_types:
            raise ValueError(
                "token_type is not a valid AuthToken type: %s" % token_type
            )

        redirection_url = kwargs.get('redirection_url', None)
        if isinstance(redirection_url, str):
            kwargs['redirection_url'] = unicode(redirection_url)

        kwargs.setdefault('token', create_unique_token_for_table())

        token = super(AuthTokenManager, self).create(**kwargs)
        token.full_clean()  # validate fields, including email
        return token


class AuthToken(models.Model):
    date_created = models.DateTimeField(
        default=datetime.datetime.utcnow, blank=True, editable=False,
        db_index=True)
    date_consumed = models.DateTimeField(blank=True, null=True, db_index=True)
    token_type = models.IntegerField(choices=TokenType._get_choices())
    token = models.TextField(unique=True)
    requester = models.ForeignKey(
        Account, db_column='requester', null=True, blank=True)
    requester_email = models.TextField(null=True, blank=True)
    email = models.TextField(db_index=True, validators=[validate_email])
    redirection_url = models.TextField(null=True, blank=True)

    displayname = DisplaynameField(null=True, blank=True)
    password = PasswordField(null=True, blank=True)

    objects = AuthTokenManager()

    class Meta:
        app_label = 'identityprovider'
        db_table = u'authtoken'

    def __unicode__(self):
        return self.token

    @property
    def absolute_url(self):
        url_name = urls_mapping.get(self.token_type, None)
        kwargs = dict(authtoken=self.token, email_address=self.email)
        if url_name is None:
            url_name = 'claim_token'
            kwargs = dict(authtoken=self.token)

        return urljoin(settings.SSO_ROOT_URL, reverse(url_name, kwargs=kwargs))

    @property
    def active(self):
        return self.date_consumed is None

    def consume(self):
        self.date_consumed = datetime.datetime.utcnow()
        self.save()

        result = AuthToken.objects.filter(
            email=self.email, token_type=self.token_type,
            requester=self.requester,
            date_consumed=None)
        now = datetime.datetime.utcnow()
        for token in result:
            token.date_consumed = now
            token.save()


def create_token(token_length):
    """Create a random token string.

    :param token_length: Specifies how long you want the token.
    """
    # Since tokens are, in general, user-visible, vowels are not included
    # below to prevent them from having curse/offensive words.
    characters = '0123456789bcdfghjklmnpqrstvwxzBCDFGHJKLMNPQRSTVWXZ'
    token = ''.join(
        random.choice(characters) for count in range(token_length))
    return unicode(token)


def create_unique_token_for_table(token_length=AUTHTOKEN_LENGTH,
                                  obj=AuthToken, column='token'):
    """Create a new unique token in a table.

    Generates a token and makes sure it does not already exist in
    the table and column specified.

    :param token_length: The length for the token string
    :param column: Database column where the token will be stored.

    :return: A new token string
    """
    token = create_token(token_length)
    try:
        params = {column: token}
        while obj.objects.get(**params) is not None:
            token = create_token(token_length)
            params = {column: token}
    except Exception:
        pass
    return token


def get_type_of_token(token_string):
    try:
        token = AuthToken.objects.get(token=token_string)
        return token.token_type
    except AuthToken.DoesNotExist:
        return None


def verify_token_string(token_string, email):
    try:
        return AuthToken.objects.get(token=token_string, email=email,
                                     date_consumed=None)
    except AuthToken.DoesNotExist:
        return None
