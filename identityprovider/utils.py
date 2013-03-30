# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from __future__ import absolute_import

import binascii
import hashlib
import random
import urllib
import urllib2
import socket
import gargoyle

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ugettext as _

SALT_LENGTH = 20


def canonical_url(obj, request=None, rootsite=None,
                  path_only_if_possible=False, view_name=None):
    """Very dumb implementation of canonical_url()."""
    from identityprovider.models import Person
    if isinstance(obj, Person):
        if view_name is None:
            return 'https://launchpad.net/~%s' % obj.name
        else:
            return 'https://launchpad.net/~%s/%s' % (obj.name, view_name)
    else:
        return None


def encrypt_launchpad_password(plaintext, salt=None):
    plaintext = str(plaintext)
    if salt is None:
        salt = generate_salt()
    v = binascii.b2a_base64(hashlib.sha1(plaintext + salt).digest() + salt)
    return v[:-1]


def generate_openid_identifier():
    # import here to avoid circular imports
    from django.db import connection
    cursor = connection.cursor()
    cursor.execute("SELECT generate_openid_identifier();")
    row = cursor.fetchone()
    return row[0]


def generate_salt():
    """ From lib/canonical/launchpad/webapp/authentication.py """
    # Salt can be any length, but not more than about 37 characters
    # because of limitations of the binascii module.
    # All 256 characters are available.
    salt = ''
    for n in range(SALT_LENGTH):
        salt += chr(random.randrange(256))
    return salt


def password_policy_compliant(password):
    return len(password) >= 8


def polite_form_errors(errors):
    if 'email' in errors:
        if errors['email'][0] == _("Enter a valid e-mail address."):
            errors['email'][0] = _("Please enter a valid email address.")


def validate_launchpad_password(plaintext, encrypted):
    encrypted = str(encrypted)
    plaintext = str(plaintext)
    try:
        ref = binascii.a2b_base64(encrypted)
    except binascii.Error:
        # Not valid base64.
        return False
    salt = ref[20:]
    v = binascii.b2a_base64(
        hashlib.sha1(plaintext + salt).digest() + salt)[:-1]
    pw1 = (v or '').strip()
    pw2 = (encrypted or '').strip()
    return pw1 == pw2


def http_request_with_timeout(url, data=None, headers=None, timeout=5):
    if data is not None:
        data = urllib.urlencode(data)
    if headers is None:
        headers = {}
    request = urllib2.Request(url, headers=headers, data=data)
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        datafile = urllib2.urlopen(request)
        data = datafile.read()
        headers = datafile.info()
    except urllib2.URLError:
        data, headers = None, None
    finally:
        socket.setdefaulttimeout(old_timeout)
    return data, headers


def get_object_or_none(qs_or_model, **kwargs):
    if hasattr(qs_or_model, 'objects'):
        qs_or_model = qs_or_model.objects
    try:
        return qs_or_model.get(**kwargs)
    except ObjectDoesNotExist:
        return None


def get_unique_username():
    from identityprovider.models.person import Person

    i = 0
    while True:
        try:
            username = "user%d" % i
            i += 1
            Person.objects.get(name=username)
        except Person.DoesNotExist:
            break
    return username


def add_user_to_team(account, teamname, nickname=None, create_team=True):
    """ Note: will not work on the staging or production databases as those are
        replicated from LP and read-only.
    """
    from identityprovider.models.person import Person
    from identityprovider.models.account import LPOpenIdIdentifier
    from identityprovider.models.team import (
        TeamParticipation, get_team_memberships_for_user)

    memberships = get_team_memberships_for_user([teamname], account, True)
    if len(memberships) > 0:
        return

    p = account.person
    if p is None:
        if nickname is None:
            nickname = get_unique_username()
        p = Person.objects.create(lp_account=account.id,
                                  displayname=account.displayname,
                                  name=nickname)

    try:
        LPOpenIdIdentifier.objects.get(lp_account=account.id)
    except LPOpenIdIdentifier.DoesNotExist:
        LPOpenIdIdentifier.objects.create(
            identifier=account.openid_identifier, lp_account=account.id)

    try:
        t = Person.objects.get(name=teamname)
    except Person.DoesNotExist:
        if not create_team:
            return
        t = Person.objects.create(displayname="Team %s" % teamname,
                                  teamowner=p.id, name=teamname)

    TeamParticipation.objects.create(team=t, person=p)


def get_current_brand():
    brand = settings.BRAND or 'ubuntu'
    # Branding can only be switched on and off it the configs are
    # using the default 'ubuntu' brand. This is because the LP
    # instance cannot run with a switch (as it uses the same DB).
    if brand == 'ubuntu':
        # As calling get_current_brand can hit the db for the
        # switch, and the DB could raise an error, we want
        # the error to be handled and displayed.
        try:
            if gargoyle.gargoyle.is_active('BRAND_LAUNCHPAD'):
                brand = 'launchpad'
            elif gargoyle.gargoyle.is_active('BRAND_UBUNTUONE'):
                brand = 'ubuntuone'
        except Exception:
            # Go with the default from the setting above.
            pass
    return brand
