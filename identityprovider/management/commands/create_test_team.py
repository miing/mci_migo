from django.core.management.base import BaseCommand
from django.conf import settings

from identityprovider.models import EmailAddress, Person
from identityprovider.models.openidmodels import OpenIDRPConfig
from identityprovider.tests import factory
from identityprovider.utils import add_user_to_team

from gargoyle.models import Switch


class Command(BaseCommand):

    help = ("Create the test user, with team membership, required for "
            "acceptance tests. Switch on gargoyle flags for experimental "
            "features.")

    def handle(self, *args, **options):
        email = settings.SSO_TEST_ACCOUNT_EMAIL
        password = settings.SSO_TEST_ACCOUNT_PASSWORD

        # hardcoded in tests
        name = 'isdtest'
        fullname = 'ISD Test'
        teams = ['canonical-voices', 'canonical-isd-hackers']
        allowed_sreg = ','.join([
            'fullname', 'nickname', 'email', 'timezone',
            'language'
        ])

        try:
            person = Person.objects.get(name=name)
            account = person.account
        except Person.DoesNotExist:
            print 'Creating test team and user account.'
            f = factory.SSOObjectFactory()
            account = f.make_account(fullname, email, password)
        finally:
            account.preferredemail = EmailAddress.objects.get(email=email)
            account.save()

        for team in teams:
            add_user_to_team(account, team, name)

        OpenIDRPConfig.objects.get_or_create(
            trust_root=settings.EMBEDDED_TRUST_ROOT,
            defaults={
                'displayname': 'test',
                'auto_authorize': False,
                'allowed_sreg': allowed_sreg,
                'allow_unverified': True,
            }
        )
        Switch.objects.get_or_create(
            key='TWOFACTOR', defaults={'status': 3})
