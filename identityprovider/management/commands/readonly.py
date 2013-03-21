# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from optparse import make_option

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.template import loader
from django.utils.translation import ugettext as _

from identityprovider.readonly import get_server_atts, update_server


def set_database_name(option, opt_str, value, parser, **kwargs):
    setattr(parser.values, 'action', kwargs['action'])
    setattr(parser.values, option.dest, value)


class Command(BaseCommand):
    option_list = BaseCommand.option_list + (
        make_option('--list', action='store_true', dest='list_servers',
                    default=False,
                    help=_('List available application servers.')),
        make_option('--all', action='store_true', dest='all_servers',
                    default=False, help=_('Select all servers.')),
        make_option('--set', action='store_const', const='set',
                    dest='action', help=_('Set server to read-only.')),
        make_option('--clear', action='store_const', const='clear',
                    dest='action', help=_('Set server to read-write.')),
        make_option('--enable', action='callback', dest='database',
                    nargs=1, type='string', callback=set_database_name,
                    callback_kwargs={'action': 'enable'},
                    help=_('Enable database.')),
        make_option('--disable', action='callback', dest='database',
                    nargs=1, type='string', callback=set_database_name,
                    callback_kwargs={'action': 'disable'},
                    help=_('Disable database.')),
    )
    help = _("""
Manage readonly mode.

options --set, --clear, --enable and --disable are all mutually exclusive.
You can only choose one at a time.
""")
    args = _('<server server ...>')

    def handle(self, *args, **options):
        list_servers = options.get('list_servers')
        all_servers = options.get('all_servers')
        action = options.get('action')
        database = options.get('database')

        # determine servers to act upon
        if all_servers:
            servers = [app['SERVER_ID'] for app in settings.APP_SERVERS]
            servers.sort()
        else:
            msgs = (
                _('Enter at least one server, or specify the --all option.'),
                _('Use --list to get a list of configured servers.'),
            )
            if not args and not list_servers:
                raise CommandError('\n  '.join(msgs))
            servers = args

        # determine action to perform
        if action is not None:
            for server in servers:
                update_server(action, server, database)
        elif not list_servers:
            msg = _('Enter one of --set, --clear, --enable or --disable.')
            raise CommandError(msg)

        # list action is special as it can be combined with the other actions
        if list_servers:
            self.show_servers()

    def show_servers(self):
        """Provides a report about readonly status of all app servers."""
        atts = get_server_atts(settings.APP_SERVERS)
        print loader.render_to_string('admin/readonly.txt', atts)
