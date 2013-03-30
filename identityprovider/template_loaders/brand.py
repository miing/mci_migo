# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from django.conf import settings
from django.template.loaders import app_directories
from django.utils._os import safe_join

from identityprovider.utils import get_current_brand


class Loader(app_directories.Loader):
    """A loader based on a feature-flag setting."""
    is_usable = True

    def get_template_sources(self, template_name, template_dirs=None):
        if not template_dirs:
            template_dirs = settings.TEMPLATE_DIRS

        brand = get_current_brand()

        for template_dir in template_dirs:
            try:
                yield safe_join(template_dir, brand, template_name)
            except UnicodeDecodeError:
                # The template dir name was a bytestring that wasn't
                # valid UTF-8.
                raise
            except ValueError:
                # The joined path was located outside of this particular
                # template_dir (it might be inside another one, so this isn't
                # fatal).
                pass
