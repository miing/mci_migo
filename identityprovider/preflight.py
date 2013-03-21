from __future__ import absolute_import

import preflight
from gargoyle import gargoyle


# Remember that the preflight may be run from the command-line or
# queried from a web-browser.  Some tests may always pass in one
# environment (e.g. if you can even *hit* the preflight page in a
# browser, you already know the DB is up), and that's okay.
#
# Make sure that each test at least works in both environment: a test
# shouldn't fail in either environment unless there's really a
# problem.

@preflight.register
class SSOPreflight(preflight.Preflight):

    def authenticate(self, request):
        return gargoyle.is_active('PREFLIGHT', request.user)

    def versions(self):
        import openid
        import identityprovider
        import piston.utils
        return [
            {'name': 'SSO', 'version': identityprovider.__version__},
            {'name': 'openid', 'version': openid.__version__},
            {'name': 'piston', 'version': piston.utils.get_version()},
        ]

    def check_database(self):
        'Are database connections accepted?'
        from django import db

        cursor = db.connection.cursor()
        cursor.execute('SELECT 42')
        cursor.fetchone()

        return True
