import sys
import os
import os.path

PATHS = [
    # sso config and src
    '.',
    'django_project',
    # dependencies
    'lib',
]

# when deployed via cfgmgr, this file (paths.py) should be located in
# <base>/branches/project
curdir = os.path.abspath(os.path.dirname(__file__))
base = os.path.abspath(os.path.join(curdir, '..'))


def get_paths(paths):
    """Sets up necessary python paths for Pay in prod/staging"""
    # only include a path if not already in sys.path to avoid duplication of
    # paths when using code reloading
    path_set = set(sys.path)
    for p in paths:
        path = os.path.join(base, p)
        if path not in path_set:
            yield path


def setup_paths():
    sys.path = list(get_paths(PATHS)) + sys.path
    os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'


if __name__ == '__main__':
    # For use in shell scripting
    # e.g. $(python paths.py)
    print "export PYTHONPATH=%s" % ":".join(get_paths(PATHS))
    print "export DJANGO_SETTINGS_MODULE=settings"
