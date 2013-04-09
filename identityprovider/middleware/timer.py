# Copyright 2011 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from time import time
import logging

from django.conf import settings

from .util import log_request


class TimerMiddleware(object):

    def process_request(self, request):
        request._time_start = time()
        return None

    def process_response(self, request, response):
        time_taken_ms = (time() - request._time_start) * 1000
        if time_taken_ms > settings.HANDLER_TIMEOUT_MILLIS:
            logging.warning('Took too long: %s' % time_taken_ms)
            log_request(request)

        return response
