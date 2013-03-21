from os import urandom
from random import randint
from string import lowercase
from time import time

from django.core.management.base import BaseCommand
from django.db import connection
from openid.store.nonce import SKEW
from optparse import make_option
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from datetime import datetime

from identityprovider.utils import encrypt_launchpad_password
from identityprovider.models.const import (
    AccountCreationRationale,
    AccountStatus,
    EmailStatus,
)


class Adaptor(object):
    """ Implements a file-like object returning the output of a function"""
    def __init__(self, generator, first_val, reps, verbosity=1):
        self.first_val = first_val
        self.reps = reps
        self.val = 0
        self.buffer = ''
        self.generator = generator
        self.verbosity = verbosity

    def read(self, n):
        while n > len(self.buffer):
            line = self.readline()
            if line == '':
                break
            self.buffer += line
        result = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return result

    def readline(self, *args):
        if self.val >= self.reps:
            return ''
        self.val += 1
        if self.val % 100000 == 0 and self.verbosity >= 2:
            print '    %s rows' % self.val
        return "\t".join(self.generator(self.val + self.first_val)) + '\n'


class Command(BaseCommand):
    option_list = BaseCommand.option_list + (
        make_option('--accounts', dest='accounts', default=1000000,
                    help='Number of random accounts to create.'),
        make_option('--sessions', dest='sessions', default=1000000,
                    help='Number of random sessions to create.'),
        make_option('--nonces', dest='nonces', default=1000000,
                    help='Number of random nonces to create.'),
        make_option('--associations', dest='associations', default=1000000,
                    help='Number of random OpenID associations to create.'),
    )
    help = "Populates the Database with a steaming pile of random data."

    def populate_table(self, tablename, rowgenerator, nrows, numeric_id=True):
        if self.verbosity >= 2:
            print "Populating %s..." % tablename
        cursor = connection.cursor()
        if not hasattr(cursor, 'copy_from'):
            raise TypeError('Use some postgresql-ish DB backend!')
        if numeric_id:
            cursor.execute("select nextval('%s_id_seq')" % tablename)
            first_val = cursor.fetchone()[0]
            self.ranges[tablename] = (first_val + 1, first_val + nrows)
        else:
            first_val = 0
            self.ranges[tablename] = (0, nrows - 1)
        adaptor = Adaptor(rowgenerator, first_val, nrows)
        cursor.copy_from(adaptor, tablename, null="NULL")
        connection.connection.commit()
        if numeric_id:
            cursor.execute("select setval('%s_id_seq', max(id)) from %s" %
                           (tablename, tablename))
        connection.connection.commit()

    def vacuum(self):
        if self.verbosity >= 2:
            print 'Vacuuming...'
        cursor = connection.cursor()
        old_isolation_level = connection.connection.isolation_level
        connection.connection.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor.execute('VACUUM ANALYZE')
        connection.connection.commit()
        connection.connection.set_isolation_level(old_isolation_level)

    def handle(self, *args, **options):
        naccounts = int(options['accounts'])
        nsessions = int(options['sessions'])
        nnonces = int(options['nonces'])
        nassociations = int(options['associations'])
        self.verbosity = int(options['verbosity'])
        self.ranges = {}
        self.openids = []
        self.passwords = []
        self.emails = []
        self.nicks = []
        self.translation_table = (lowercase * 10)[:256]

        self.populate_table('lp_openididentifier',
                            self.gen_lp_openididentifier, naccounts,
                            numeric_id=False)
        self.populate_table('lp_person', self.gen_lp_person, naccounts)
        self.populate_table('account', self.gen_account, naccounts)
        self.populate_table('accountpassword', self.gen_accountpassword,
                            naccounts)
        self.populate_table('emailaddress', self.gen_emailaddress, naccounts)
        self.populate_table('django_session', self.gen_session, nsessions,
                            numeric_id=False)
        self.populate_table('openidnonce', self.gen_nonce, nnonces,
                            numeric_id=False)
        self.populate_table('openidassociation', self.gen_association,
                            nassociations, numeric_id=False)
        self.vacuum()
        if self.verbosity >= 1:
            print "Nick, email, password, openid_identifier"
            for row in zip(self.nicks, self.emails, self.passwords,
                           self.openids):
                print ', '.join(['"%s"' % x for x in row])

    def random_string(self, size):
        msg = urandom(size)
        return msg.translate(self.translation_table)

    def random_date(self):
        year = randint(2009, 2010)
        month = randint(1, 12)
        day = randint(1, 28)
        return str(datetime(year, month, day))

    def random_email(self):
        base = self.random_string(20)
        return '%s@%s.%s' % (base[:9], base[9:17], base[17:])

    def random_account_id(self):
        return str(randint(*self.ranges['account']))

    def random_handle(self):
        parts = self.random_string(14)
        return "{HMAC-SHA1}{%s}{%s==}" % (parts[:8], parts[8:])

    def gen_account(self, id):
        """Return a sequence representing an Account.

        Currently (id, date_created, creation_rationale, status,
            date_status_set, displayname, openid_identifier,
            status_comment, preferredlanguage, old_openid_identifier,
            twofactor_required, twofactor_attempts, warn_about_backup_device)
        """
        date_created = self.random_date()
        nick = self.nicks[id - self.ranges['account'][0]]
        name = (nick + ' ' + nick).title()
        openid = self.openids[id - self.ranges['account'][0]]
        return [str(id), date_created,
                str(AccountCreationRationale.USER_CREATED),
                str(AccountStatus.ACTIVE), date_created, name, openid, '',
                'NULL', '', 'False', '0', 'True']

    def gen_accountpassword(self, id):
        """Return a sequence representing an AccountPassword.

        Currently (id, account, password)
        """
        account_id = (id - self.ranges['accountpassword'][0] +
                      self.ranges['account'][0])
        plaintext = self.random_string(size=8)
        self.passwords.append(plaintext)
        password = encrypt_launchpad_password(plaintext)
        return [str(id), str(account_id), password]

    def gen_lp_openididentifier(self, id):
        """ Returns a sequence representing an LPOpenIdIdentfier.

        Currently (id, openid, date_created)
        """
        openid = self.random_string(size=10)
        self.openids.append(openid)
        return [openid, str(id), self.random_date()]

    def gen_lp_person(self, id):
        """ Returns a sequence representing a Person.

        Currently (id, displayname, teamowner, teamdescription, name,
            language, fti, defaultmembershipperiod, defaultrenewalperiod,
            subscriptionpolicy, merged, datecreated, addressline1,
            addressline2, organization, city, province, country, postcode,
            phone, homepage_content, icon, mugshot, hide_email_addresses,
            creation_rationale, creation_comment, registrant, logo,
            renewal_policy, personal_standing, personal_standing_reason,
            mail_resumption_date, mailing_list_auto_subscribe_policy,
            mailing_list_receive_duplicates, visibility,
            verbose_bugnotifications, account)
        """
        displayname = self.random_string(12)
        nick = self.random_string(8) + str(id)
        self.nicks.append(nick)
        datecreated = self.random_date()
        account_id = (id - self.ranges['lp_person'][0] +
                      self.ranges['lp_openididentifier'][0])
        return [
            str(id), displayname, 'NULL', '', nick, 'NULL', '', '0', '0',
            '1', 'NULL', datecreated, '', '', '', '', '', 'NULL', '',
            '', '', 'NULL', 'NULL', 'f',
            str(AccountCreationRationale.USER_CREATED), '', 'NULL', 'NULL',
            '10', '0', '', 'NULL', '1', 't', '1', 'f', str(account_id),
        ]

    def gen_emailaddress(self, id):
        """ Returns a sequence representing an EmailAddress.

        Currently (id, email, lp_person, status, date_created, account)
        """
        account_id = (id - self.ranges['emailaddress'][0] +
                      self.ranges['account'][0])
        person_id = (id - self.ranges['emailaddress'][0] +
                     self.ranges['lp_person'][0])
        email = self.random_email()
        self.emails.append(email)
        date_created = self.random_date()
        return [str(id), email, str(person_id), str(EmailStatus.PREFERRED),
                date_created, str(account_id)]

    def gen_session(self, id):
        """ Returns a sequence representing a Django session.

        Currently (session_key, session_data, expire_date).
        """
        idstr = self.random_string(size=12) + str(id)
        return[idstr, self.random_string(size=200), self.random_date()]

    def gen_nonce(self, id):
        """ Returns a sequence representing an OpenID nonce.

        Currently (server_url, timestamp, salt).
        """
        now = int(time())
        timestamp = str(randint(now - SKEW * 10, now + SKEW))
        server_url = 'http://localhost/|' + self.random_string(30)
        return[server_url, timestamp, self.random_string(30)]

    def gen_association(self, id):
        """ Returns a sequence representing an OpenIDAssociation.

        Currently (server_url, handle, secret, issued, lifetime, assoc_type).
        """
        now = int(time())
        issued = str(randint(now - SKEW * 1000, now - 1))
        return ['http://localhost/|normal', self.random_handle(),
                self.random_string(40), issued, '1209600', 'HMAC-SHA1']
