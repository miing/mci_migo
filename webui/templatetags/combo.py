# Copyright 2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django import template
from django.conf import settings
from django.template import TemplateSyntaxError
from django.template.base import Node
from django.template.defaulttags import kwarg_re

register = template.Library()


css_template = ('<link href="{0}" rel="stylesheet" type="text/css" '
                'media="screen" />')

js_template = '<script type="text/javascript" src="{0}"></script>'

# XXX Once we move beyond django 1.3 we can just use a simple_tag
# which will handle *args and **kwargs with half the code.


@register.tag
def combo(parser, token):
    """Parse the args and kwargs - based on django's url tag."""
    bits = token.split_contents()
    tagname = bits[0]
    if len(bits) < 2:
        raise TemplateSyntaxError(
            "'%s' takes at least one argument." % tagname)

    filenames = []
    options = {}
    bits = bits[1:]
    for bit in bits:
        match = kwarg_re.match(bit)
        if not match:
            raise TemplateSyntaxError(
                "Malformed arguments to '{0}' tag.".format(tagname))
        name, value = match.groups()
        if name:
            options[name] = parser.compile_filter(value)
        else:
            filenames.append(parser.compile_filter(value))

    return ComboNode(filenames, options)


class ComboNode(Node):

    def __init__(self, filenames, options):
        self.filenames = filenames
        self.options = options

    def render(self, context):
        filenames = [f.resolve(context) for f in self.filenames]
        options = dict([(k, v.resolve(context))
                       for k, v in self.options.items()])
        prefix = options.get('prefix', '').strip('/')
        template = css_template
        if filenames[0].endswith('.js'):
            template = js_template

        filenames = [f.strip('/') for f in filenames]
        if prefix:
            filenames = [
                '/'.join([prefix, filename]) for filename in filenames]

        if len(filenames) == 1 or not settings.COMBINE:
            return "\n".join([
                template.format(settings.STATIC_URL + f) for f in filenames])

        url = settings.COMBO_URL + '?' + '&'.join(filenames)
        return template.format(url)
