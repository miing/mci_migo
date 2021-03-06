from optparse import make_option

from django.core.management.base import BaseCommand, CommandError

from identityprovider.models import OpenIDRPConfig


class Command(BaseCommand):
    args = '<trust_root>'
    option_list = BaseCommand.option_list + (
        make_option('--allow-unverified', action="store_true",
                    default=False, dest='allow_unverified'),
        make_option('--allowed-user-attribs', action="store",
                    dest='allowed_user_attribs'))
    help = "Create OpenID RP config entry."

    def handle(self, *args, **kwargs):
        if len(args) < 1:
            raise CommandError("Need to specify trust_root")

        trust_root = args[0]
        allow_unverified = kwargs.get('allow_unverified', False)
        allowed_user_attribs = kwargs.get('allowed_user_attribs', '')
        if allowed_user_attribs is None:
            allowed_user_attribs = ''
        OpenIDRPConfig.objects.create(
            trust_root=trust_root, allow_unverified=allow_unverified,
            allowed_user_attribs=allowed_user_attribs)
