import csv
import logging
import textwrap

from django.core.management.base import BaseCommand
from optparse import make_option

from identityprovider.models import (
    AuthenticationDevice,
    Person,
)


class Command(BaseCommand):
    option_list = BaseCommand.option_list + (
        make_option('--keys', dest='keys', help='CSV file with SN<->Key data'),
        make_option('--users', dest='users',
                    help='CSV file with SN<->lp_username data'),
    )
    help = textwrap.dedent("""
    Uploads key fobs as two factor devices.
    Needs two csv files, with headers SN,key and SN,user respectively
    """)

    def handle(self, *args, **options):
        keys = users = {}
        with open(options['keys']) as keyfile:
            keys = dict((r['SN'], r['key']) for r in csv.DictReader(keyfile))
        with open(options['users']) as userfile:
            users = dict((r['SN'], r['user'])
                         for r in csv.DictReader(userfile))

        for SN, lpname in users.items():
            try:
                person = Person.objects.get(name=lpname)
                if person.account is None:
                    logging.warn('Could not locate account for %s' % lpname)
                else:
                    device = AuthenticationDevice.objects.create(
                        account=person.account,
                        name='Canonical Key Fob %s' % SN,
                        key=keys[SN],
                        counter=0
                    )
                    device.save()
            except Person.DoesNotExist:
                logging.warn('User %s not found' % lpname)
            except KeyError:
                logging.warn('Fob SN %s key not found' % SN)
            except Exception as e:
                logging.error(
                    'Error for fob %s for user %s: %s' % (SN, lpname, e)
                )
