# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django import template

register = template.Library()


@register.inclusion_tag('menu_item.html', takes_context=True)
def menu_item(context, section, label, link):
    return {'current_section': context.get('current_section', None),
            'section': section,
            'label': label,
            'link': link}
