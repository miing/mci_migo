from optparse import make_option
from django.core.management.base import NoArgsCommand
from django.conf import settings

from gargoyle.models import Switch, DISABLED, GLOBAL


class Command(NoArgsCommand):
    help = 'Lists the gargoyle switches'
    FORMAT = "{:<30} {:<10}"

    option_list = NoArgsCommand.option_list + (
        make_option(
            '--short',
            action='store_true',
            default=False,
            dest='short',
            help='Only output semicolon separated list of active flags'),
    )

    def handle(self, *args, **kwargs):
        short = kwargs.pop('short', False)
        fmt = self.FORMAT.format
        switches = dict(
            (sw.key, (sw.status, False)) for sw in Switch.objects.all()
        )
        for switch, config in settings.GARGOYLE_SWITCH_DEFAULTS.items():
            if switch not in switches:
                status = GLOBAL if config.get('is_active', False) else DISABLED
                switches[switch] = (status, True)

        output = []
        if not short:
            header = fmt("Name", "Status")
            output.append(header)
            output.append("-" * len(header))

        for switch in sorted(switches):
            status, default = switches[switch]
            if short:
                if status == GLOBAL:
                    output.append(switch)
            else:
                text_status = Switch.STATUS_CHOICES[status - 1][1]
                if default:
                    text_status += " (default value)"
                output.append(fmt(switch, text_status))

        join_char = ";" if short else "\n"
        return join_char.join(output) + "\n"
