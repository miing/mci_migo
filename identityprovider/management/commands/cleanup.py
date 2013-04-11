# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import time
from datetime import date, datetime, timedelta
from optparse import make_option

import openid.store.nonce
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection, transaction
from django.utils.translation import ugettext as _

from identityprovider.models import Account, EmailAddress


SESSION_SQL = """DELETE FROM django_session
WHERE session_key = ANY(SELECT session_key FROM django_session
                        WHERE expire_date < CURRENT_TIMESTAMP LIMIT %s)"""
NONCES_SQL = """DELETE FROM openidnonce
WHERE timestamp = ANY(SELECT timestamp FROM openidnonce
                      WHERE timestamp < %s LIMIT %s)"""
NO_ITEMS = """No items selected to clean up. Please select at least one of:

--sessions
--nonces
--testdata
"""


class Command(BaseCommand):

    option_list = BaseCommand.option_list + (
        make_option('-s', '--sessions', dest='sessions', default=False,
                    action='store_true', help='Cleanup sessions.'),
        make_option('-n', '--nonces', dest='nonces', default=False,
                    action='store_true', help='Cleanup nonces.'),
        make_option('-t', '--testdata', dest='testdata', default=False,
                    action='store_true', help='Cleanup test data.'),
        make_option('-l', '--limit', dest='limit', default=10000,
                    action='store',
                    help='Number of rows to process per batch.'),
        make_option('-d', '--date-created', dest='date_created',
                    default=None, action='store',
                    help='Cleanup records created before this date.'),
    )
    help = _("""Clean unnecessary/stalled data from database.""")

    def handle(self, *args, **options):
        limit = int(options['limit'])
        nonce_expire_stamp = int(time.time()) - openid.store.nonce.SKEW
        test_email_pattern = settings.EMAIL_ADDRESS_PATTERN.replace(
            '+', '\+').replace('.', '\.') % "[^@]+"
        if options['date_created'] is None:
            date_created = date.today() + timedelta(days=1)
        else:
            parsed = datetime.strptime(options['date_created'], '%Y-%m-%d')
            date_created = parsed.date()
        queries = {
            'sessions': SESSION_SQL % limit,
            'nonces': NONCES_SQL % (nonce_expire_stamp, limit),
        }
        verbosity = int(options['verbosity'])

        testdata = options.get('testdata')
        if testdata:
            self.clean_testdata(test_email_pattern, date_created, limit,
                                verbosity)

        selected_queries = [query for query in queries
                            if options.get(query)]
        if not selected_queries and not testdata:
            self.stdout.write(NO_ITEMS)

        for item in selected_queries:
            if verbosity >= 1:
                self.stdout.write("\nCleaning %s..." % item)
            cursor = connection.cursor()
            cursor.execute(queries[item])
            while cursor.rowcount > 0:
                if verbosity >= 2:
                    self.stdout.write(".")
                cursor.execute(queries[item])
            transaction.commit_unless_managed()

    def clean_testdata(self, email_pattern, date_created, limit, verbosity=0):
        kwargs = {'email__iregex': email_pattern,
                  'date_created__lt': date_created}

        if verbosity >= 1:
            self.stdout.write("\nCleaning accounts...\n")

        while True:
            email_ids = EmailAddress.objects.filter(**kwargs).values_list(
                'pk')[:limit]
            accounts = Account.objects.filter(emailaddress__in=email_ids)
            if not accounts:
                break

            if verbosity >= 2:
                self.stdout.write("\tDeleting %d accounts..." % (
                    accounts.count(),))
            accounts.delete()
            if verbosity >= 2:
                self.stdout.write('\t [OK]\n')
