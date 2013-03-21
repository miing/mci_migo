from optparse import make_option

from django.core.management.base import BaseCommand, CommandError

from identityprovider.models import Account, EmailAddress
from identityprovider.utils import add_user_to_team


class Command(BaseCommand):
    args = '<team team ...>'
    option_list = BaseCommand.option_list + (
        make_option('--email', dest='email'),
        make_option('--openid', dest='openid'))
    help = "Link an account and a team."

    def handle(self, *args, **kwargs):
        email = kwargs.get('email')
        openid = kwargs.get('openid')

        if email is not None:
            try:
                account = EmailAddress.objects.get(email=email).account
            except EmailAddress.DoesNotExist:
                raise CommandError("Email '%s' does not exist" % email)
        elif openid is not None:
            try:
                account = Account.objects.get(openid_identifier=openid)
            except Account.DoesNotExist:
                raise CommandError(
                    "Account with openid '%s' does not exist" % openid)
        else:
            raise CommandError("Need to specify --email or --openid")

        for team in args:
            add_user_to_team(account, team, create_team=False)
