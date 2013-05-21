# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import base64
import hashlib
import json
import time

from datetime import datetime
from openid.association import Association

import openid.store
import openid.store.nonce

from gargoyle import gargoyle
from openid.store.interface import OpenIDStore

from django.conf import settings
from django.core.cache import cache
from django.db import models
from django.utils.translation import ugettext_lazy as _

from identityprovider.models import Account
from identityprovider.models.const import AccountCreationRationale

__all__ = (
    'OpenIDAssociation',
    'OpenIDAuthorization',
    'OpenIDNonce',
    'OpenIDRPConfig',
    'OpenIDRPSummary',
    'DjangoOpenIDStore',
)


class OpenIDAssociation(models.Model):
    server_url = models.CharField(max_length=2047)
    handle = models.CharField(max_length=255, primary_key=True)
    secret = models.TextField()
    issued = models.IntegerField()
    lifetime = models.IntegerField()
    assoc_type = models.CharField(max_length=64)

    class Meta:
        app_label = 'identityprovider'
        db_table = u'openidassociation'
        unique_together = ('server_url', 'handle')


class OpenIDAuthorizationManager(models.Manager):

    def authorize(self, account, trust_root, expires=None, client_id=None):
        if settings.READ_ONLY_MODE:
            return
        if expires is None:
            expires = datetime.utcnow()
        try:
            existing = OpenIDAuthorization.objects.get(
                account=account,
                client_id=client_id,
                trust_root=trust_root)
            existing.date_created = datetime.utcnow()
            existing.date_expires = expires
            existing.save()
        except OpenIDAuthorization.DoesNotExist:
            OpenIDAuthorization.objects.create(
                account=account,
                client_id=client_id,
                trust_root=trust_root,
                date_expires=expires)

    def is_authorized(self, account, trust_root, client_id):
        client_none = OpenIDAuthorization.objects.filter(
            account__exact=account,
            trust_root__exact=trust_root,
            client_id__exact=None,
            date_expires__gte=datetime.utcnow()).count()
        if client_none > 0:
            return True
        else:
            client_match = OpenIDAuthorization.objects.filter(
                account__exact=account,
                trust_root__exact=trust_root,
                client_id__exact=client_id,
                date_expires__gte=datetime.utcnow()).count()
            if client_match > 0:
                return True
        return False


class OpenIDAuthorization(models.Model):
    account = models.ForeignKey(Account, db_column='account')
    client_id = models.TextField(blank=True, null=True)
    date_created = models.DateTimeField(
        default=datetime.utcnow, blank=True, editable=False)
    date_expires = models.DateTimeField()
    trust_root = models.TextField()

    objects = OpenIDAuthorizationManager()

    class Meta:
        app_label = 'identityprovider'
        db_table = u'openidauthorization'


class OpenIDNonce(models.Model):
    server_url = models.CharField(max_length=2047, primary_key=True)
    timestamp = models.IntegerField()
    salt = models.CharField(max_length=40)

    class Meta:
        app_label = 'identityprovider'
        db_table = 'openidnonce'
        unique_together = ('server_url', 'timestamp', 'salt')


class OpenIDRPConfigManager(models.Manager):

    def for_url(self, url):
        if url is None:
            return None
        elif url.endswith('/'):
            url = url[:-1]
        # We need to encode the % character in URLs, so that an
        # attacker can't maliciously take advantage of it as a
        # wildcard.  To do this, we select an escape character (~),
        # and then escape it as ~T and % as ~P.
        #
        # Although this hole only exists in the right-hand argument of
        # LIKE, this replacement happens in both the received URL and
        # the recorded trust_root, in case they have legitimate ~
        # characters that need to be matched.
        #
        # Python uses % for parameters in interpolated strings, and
        # PostgreSQL uses it as a wild card in LIKE-patterns; so
        # they're escaped here.
        condition = """
      rtrim(trust_root, '/') = %s OR
      replace(replace(%s,         '~', '~T'), '%%', '~P')
LIKE (replace(replace(trust_root, '~', '~T'), '%%', '~P') || '%%')
"""

        q = self.extra(
            select={'len': 'length(trust_root)'},
            where=[condition],
            params=(url, url),
            order_by=['-len']  # Select the longest match
        )
        return q[0] if q else None


class OpenIDRPConfig(models.Model):
    trust_root = models.TextField(unique=True)
    displayname = models.TextField()
    description = models.TextField()
    logo = models.TextField(blank=True, null=True)
    allowed_user_attribs = models.TextField(blank=True, null=True)
    allowed_ax = models.TextField(blank=True, null=True)
    allowed_sreg = models.TextField(blank=True, null=True)
    creation_rationale = models.IntegerField(
        default=13, choices=AccountCreationRationale._get_choices())
    can_query_any_team = models.BooleanField(default=False)
    auto_authorize = models.BooleanField(default=False)
    # TODO: remove once all rpconfig entries have been migrated to use
    # flag_twofactor
    require_two_factor = models.BooleanField(default=False)
    ga_snippet = models.TextField(blank=True, null=True)
    prefer_canonical_email = models.BooleanField(default=False)
    allow_unverified = models.BooleanField(default=False)

    # flags
    flag_twofactor = models.CharField(max_length=256, blank=True, null=True)

    class Meta:
        app_label = 'identityprovider'
        db_table = 'ssoopenidrpconfig'
        verbose_name = _('OpenID RP Config')
        verbose_name_plural = _('OpenID RP Configs')

    objects = OpenIDRPConfigManager()

    def __unicode__(self):
        return self.displayname

    @classmethod
    def cache_key(cls, trust_root):
        # Need to calculate digest of the url to make it work with long
        # trust_root values when caching in memcached
        return 'rpconfig-' + hashlib.md5(trust_root.rstrip('/')).hexdigest()

    def save(self, *args, **kwargs):
        cache.delete(self.cache_key(self.trust_root))
        return super(OpenIDRPConfig, self).save(*args, **kwargs)

    @property
    def logo_url(self):
        if self.logo:
            if self.logo.startswith('http'):
                return self.logo
            else:
                return settings.MEDIA_URL + self.logo
        else:
            return None

    def twofactor_required(self, request):
        flag = self.flag_twofactor
        if not flag:
            return self.require_two_factor
        return gargoyle.is_active(flag, request)


class OpenIDRPSummaryManager(models.Manager):

    def record(self, account, trust_root, openid_identifier=None,
               approved_data=None):
        if settings.READ_ONLY_MODE:
            return None
        if openid_identifier is None:
            openid_identifier = account.openid_identity_url
        if approved_data:
            approved_data = json.dumps(approved_data)
        try:
            summary = OpenIDRPSummary.objects.get(
                account=account,
                trust_root=trust_root,
                openid_identifier=openid_identifier)
            update_bits = dict(
                total_logins=models.F('total_logins') + 1,
                date_last_used=datetime.utcnow(),
            )
            if approved_data:
                update_bits['approved_data'] = approved_data
            # Using update is not causing Django to select the record once
            # again from the database, it's one less SELECT.
            OpenIDRPSummary.objects.filter(pk=summary.pk).update(**update_bits)
        except OpenIDRPSummary.DoesNotExist:
            summary = OpenIDRPSummary(
                account=account,
                trust_root=trust_root,
                openid_identifier=openid_identifier)
            if approved_data:
                summary.approved_data = approved_data
            summary.save()
        return summary


class OpenIDRPSummary(models.Model):
    account = models.ForeignKey(Account, db_column='account')
    openid_identifier = models.TextField(db_index=True)
    trust_root = models.TextField(db_index=True)
    date_created = models.DateTimeField(
        default=datetime.utcnow, blank=True, editable=False)
    date_last_used = models.DateTimeField(
        default=datetime.utcnow, blank=True, editable=False)
    total_logins = models.IntegerField(default=1)
    approved_data = models.TextField(blank=True, null=True, default='')

    objects = OpenIDRPSummaryManager()

    class Meta:
        app_label = 'identityprovider'
        db_table = u'openidrpsummary'
        unique_together = ('account', 'trust_root', 'openid_identifier')

    def get_approved_data(self):
        try:
            data = json.loads(self.approved_data)
        except (TypeError, ValueError):
            data = {}

        if not data.get('user_attribs'):
            # fallback to read from old ax/sreg approved data
            ax_data = data.get('ax', {})
            requested_ax = set(ax_data.get('requested', []))
            approved_ax = set(ax_data.get('approved', []))
            sreg_data = data.get('sreg', {})
            requested_sreg = set(sreg_data.get('requested', []))
            approved_sreg = set(sreg_data.get('approved', []))

            data['user_attribs'] = {
                'requested': list(requested_ax | requested_sreg),
                'approved': list(approved_ax | approved_sreg),
            }
            self.approved_data = json.dumps(data)
            self.save()
        return data

    def set_approved_data(self, approved_data):
        if not isinstance(approved_data, basestring):
            approved_data = json.dumps(approved_data)
        self.approved_data = approved_data


class DjangoOpenIDStore(OpenIDStore):
    """
    The Python openid library needs an OpenIDStore subclass to persist data
    related to OpenID authentications. This one uses our Django models.

    From: http://code.google.com/p/django-openid/source/browse/trunk/
                                                        django_openid/models.py

    Please see the license file in thirdparty/django-openid.
    """

    def storeAssociation(self, server_url, association):
        try:
            assoc = OpenIDAssociation.objects.get(
                server_url=server_url,
                handle=association.handle)
            assoc.secret = base64.b64encode(association.secret)
            assoc.issued = association.issued
            assoc.lifetime = association.getExpiresIn()
            assoc.assoc_type = association.assoc_type
        except OpenIDAssociation.DoesNotExist:
            assoc = OpenIDAssociation(
                server_url=server_url,
                handle=association.handle,
                secret=base64.b64encode(association.secret),
                issued=association.issued,
                lifetime=association.getExpiresIn(),
                assoc_type=association.assoc_type)
        assoc.save()

    def getAssociation(self, server_url, handle=None):
        assocs = []
        if handle is not None:
            assocs = OpenIDAssociation.objects.filter(
                server_url=server_url,
                handle=handle
            )
        else:
            assocs = OpenIDAssociation.objects.filter(
                server_url=server_url)
        if not assocs:
            return None
        associations = []
        for assoc in assocs:
            association = Association(
                assoc.handle, base64.b64decode(str(assoc.secret)),
                assoc.issued, assoc.lifetime, assoc.assoc_type)
            if association.getExpiresIn() == 0:
                self.removeAssociation(server_url, assoc.handle)
            else:
                associations.append((association.issued, association))
        if not associations:
            return None
        return associations[-1][1]

    def removeAssociation(self, server_url, handle):
        assocs = list(OpenIDAssociation.objects.filter(
            server_url=server_url, handle=handle))
        assocs_exist = len(assocs) > 0
        for assoc in assocs:
            assoc.delete()
        return assocs_exist

    def useNonce(self, server_url, timestamp, salt):
        # Has nonce expired?
        if abs(timestamp - time.time()) > openid.store.nonce.SKEW:
            return False
        try:
            nonce = OpenIDNonce.objects.get(
                server_url__exact=server_url,
                timestamp__exact=timestamp,
                salt__exact=salt)
        except OpenIDNonce.DoesNotExist:
            nonce = OpenIDNonce.objects.create(
                server_url=server_url,
                timestamp=timestamp,
                salt=salt)
            return True
        nonce.delete()
        return False

    def cleanupNonce(self):
        OpenIDNonce.objects.filter(
            timestamp__lt=(
                int(time.time()) - openid.store.nonce.SKEW)).delete()

    def cleanupAssociations(self):
        OpenIDAssociation.objects.extra(
            where=[
                '(issued + lifetime) < (%s)' % time.time()]).delete()
