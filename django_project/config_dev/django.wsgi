import os
import platform
import sys

# before doing anything else, patch stdout to avoid breakage in production
# see LP: #1099459 for details
sys.stdout = sys.stderr

# add path to sttings to system path if not already there
# check if path is already there to avoid path duplication when
# modwsgi is configured for code reloading
curdir = os.path.abspath(os.path.dirname(__file__))
if curdir not in sys.path:
    sys.path.append(curdir)
import paths
paths.setup_paths()

from canonical.oops.wsgi import OopsWare
from django.conf import settings
from django.core.handlers.wsgi import WSGIHandler

os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

#
# add extra paths to system path if not already there
# check if path is already there to avoid path duplication when
# modwsgi is configured for code reloading
extra_paths = [path for path in settings.EXTRA_PYTHONPATH
               if path not in sys.path]
sys.path.extend(extra_paths)

os.environ['PGCONNECT_TIMEOUT'] = str(settings.PGCONNECT_TIMEOUT)

from identityprovider.wsgi_handler import OOPSWSGIHandler

app = OOPSWSGIHandler()

# Wrap the application in the Oops wsgi app to catch unhandled exceptions
# and create oops for them.
#
# First we create the config that defines what to do with the oopses.
import oops_dictconfig
from oops_wsgi import make_app, install_hooks

config = oops_dictconfig.config_from_dict(settings.OOPSES)
install_hooks(config)

# Then we wrap the django app in the oops one
application = make_app(app, config, oops_on_status=['500'])
