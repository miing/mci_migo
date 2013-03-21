from django.core.management import call_command
from django.contrib.sessions.models import Session
from django.db import connection
from django.test import TestCase

from identityprovider.models import (
    Account,
    AccountPassword,
    EmailAddress,
    LPOpenIdIdentifier,
    OpenIDAssociation,
    OpenIDNonce,
    Person,
)
from identityprovider.tests.utils import skipOnSqlite


SQL = """TRUNCATE lp_openididentifier, account,
         accountpassword, emailaddress, lp_person, django_session,
         openidnonce, openidassociation CASCADE"""


@skipOnSqlite
class PopulateCommandTestCase(TestCase):

    def tearDown(self):
        cursor = connection.cursor()
        cursor.execute(SQL)
        connection.connection.commit()

    setUp = tearDown

    def check_populate_populates_correctly(self, naccounts=0, nsessions=0,
                                           nnonces=0, nassociations=0):
        self.assertEqual(0, LPOpenIdIdentifier.objects.count())
        self.assertEqual(0, Account.objects.count())
        self.assertEqual(0, AccountPassword.objects.count())
        self.assertEqual(0, EmailAddress.objects.count())
        self.assertEqual(0, Person.objects.count())
        self.assertEqual(0, Session.objects.count())
        self.assertEqual(0, OpenIDNonce.objects.count())
        self.assertEqual(0, OpenIDAssociation.objects.count())

        call_command('populate', accounts=naccounts, sessions=nsessions,
                     nonces=nnonces, associations=nassociations, verbosity=0)

        self.assertEqual(naccounts, LPOpenIdIdentifier.objects.count())
        self.assertEqual(naccounts, Account.objects.count())
        self.assertEqual(naccounts, AccountPassword.objects.count())
        self.assertEqual(naccounts, EmailAddress.objects.count())
        self.assertEqual(naccounts, Person.objects.count())
        self.assertEqual(nsessions, Session.objects.count())
        self.assertEqual(nnonces, OpenIDNonce.objects.count())
        self.assertEqual(nassociations, OpenIDAssociation.objects.count())

    def test_populate_accounts(self):
        self.check_populate_populates_correctly(naccounts=15)

    def test_populate_sessions(self):
        self.check_populate_populates_correctly(nsessions=15)

    def test_populate_nonces(self):
        self.check_populate_populates_correctly(nnonces=15)

    def test_populate_associations(self):
        self.check_populate_populates_correctly(nassociations=15)
