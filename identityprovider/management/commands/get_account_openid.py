# Copyright 2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.core.management.base import LabelCommand, CommandError

from identityprovider.models import Person
from identityprovider.utils import get_object_or_none


class Command(LabelCommand):

    help = "Return the openid identifier for a given list of LP usernames."

    def handle_label(self, label, **options):
        username = label
        person = get_object_or_none(Person, name=username)
        if person is None:
            raise CommandError(
                "No LP account found matching username '%s'." % username)

        account = person.account
        if account is None:
            raise CommandError(
                "LP account matching username '%s' is not linked to any SSO "
                "account." % username)

        return "%s,%s" % (username, account.openid_identifier)
