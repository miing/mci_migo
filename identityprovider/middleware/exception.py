# Copyright 2011 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import logging
import sys
import traceback

from .util import log_request


class ConsoleExceptionMiddleware(object):
    def process_exception(self, request, exception):
        traceback.print_exc(file=sys.stdout)


class LogExceptionMiddleware(object):

    def process_exception(self, request, exception):
        logging.exception('Unhandled exception in application')
        log_request(request, log_exception_trace=True)
