# Copyright 2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from optparse import make_option

from django.core.management.base import BaseCommand, CommandError

from identityprovider.models import Person
from identityprovider.utils import get_object_or_none


class Command(BaseCommand):

    option_list = BaseCommand.option_list + (
        make_option('-u', '--username', dest='username',
                    action='store', help='LP username.'),
    )
    help = "Return the openid identifier for a given LP username."

    def handle(self, *args, **options):
        username = options.get('username')
        if not username:
            raise CommandError('Need to specify a username.')

        person = get_object_or_none(Person, name=username)
        if person is None:
            raise CommandError(
                "No LP account found matching username '%s'." % username)

        account = person.account
        if account is None:
            raise CommandError(
                "LP account matching username '%s' is not linked to any SSO "
                "account." % username)

        self.stdout.write(account.openid_identifier)
