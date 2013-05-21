# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import json
from django import template

register = template.Library()


def commands_are_valid(commands):
    if not isinstance(commands, list):
        return False
    if not all(isinstance(x, list) for x in commands):
        return False
    for command in commands:
        if not all(isinstance(x, basestring) for x in command):
            return False
        for char in "'\"\n":
            if any(char in arg for arg in command):
                return False
    return True


@register.simple_tag
def expand_ga_commands(snippet):
    try:
        commands = json.loads(snippet)
    except (ValueError, TypeError):
        return ''
    if not commands_are_valid(commands):
        return ''

    pattern = "_gaq.push([%s]);"
    output = []
    for command in commands:
        # The django simplejson leaves strings as byte-strings,
        # whereas the standard library json decodes to Unicode.
        # We decode to Unicode if necessary to ensure consistency of output.
        new_command = [
            arg if isinstance(arg, unicode) else arg.decode('utf-8')
            for arg in command
        ]
        output.append(pattern % ', '.join(["'%s'" % x for x in new_command]))

    return "\n".join(output)
