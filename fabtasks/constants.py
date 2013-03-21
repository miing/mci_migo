APPS = [
    "api",
    "identityprovider",
    "webui",
]
PG_VERSION = '9.1'
BUILD_DEPENDENCIES = [
    'libpq-dev',
    'libxml2-dev',
    'libxslt1-dev',
    'memcached',
    "postgresql-plpython-%s" % PG_VERSION,
    'python-dev',
    'python-m2crypto',
    'swig',
    'config-manager',
]
PSYCOPG2_CONFLICTS = ['python-egenix-mx-base-dev']
TRANSLATIONS_BRANCH = (
    'lp:~canonical-isd-hackers/canonical-identity-provider/translations')
VIRTUALENV = '.env'

try:
    import cProfile
except ImportError:
    BUILD_DEPENDENCIES.append('python-profiler')
