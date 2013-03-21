# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.conf import settings
from django.utils.translation import ugettext as _

from identityprovider.readonly import ReadOnlyManager
# XXX: should not depend on webui
from webui.views.errors import ErrorPage


class NoBackupError(Exception):
    pass


class DBFailoverMiddleware(object):
    """Database failover middleware.

    This middleware will attempt to establish a minimal connection to the
    configured database before starting each request.  If it fails for
    some reason, it will enter readonly mode and switch to some other
    configured backup database.

    Available database connections are configured with the DB_CONNECTIONS
    setting, which is a list of dictionaries, each with ID, HOST, PORT, NAME,
    USER and PASSWORD keys.

    When the main database connection fails, the backup connections
    are tried in order.
    """

    def process_request(self, request):
        romanager = ReadOnlyManager()
        try:
            connection_ok = False
            failed_attempts = 0
            max_attempts = getattr(settings, 'DBFAILOVER_ATTEMPTS', 1)
            romanager.check_readonly()
            self.choose_connection(romanager)
            while not connection_ok:
                connection_ok = romanager.ping_current_connection()
                if not connection_ok:
                    failed_attempts += 1
                    if failed_attempts == max_attempts:
                        romanager.mark_current_failed(automatic=True)
                        self.choose_connection(romanager)
                        failed_attempts = 0
        except NoBackupError:
            page = ErrorPage(500, errormsg="No backup connections left.")
            return page(request)

    def process_response(self, request, response):
        """ Add a http header to indicate if we're currently in RO-mode """
        if settings.DEBUG:
            response['X-Read-Only'] = str(settings.READ_ONLY_MODE)
        return response

    def choose_connection(self, romanager):
        """ Configure the first database connection that isn't already marked
        as failed, if any.
        """
        for db in romanager.connections:
            if not romanager.is_failed(db['ID']):
                romanager.set_db(db)
                break
        else:
            raise NoBackupError(_("No backup connections left"))
