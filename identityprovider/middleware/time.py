# Copyright 2011 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import datetime
import logging as log

from django.conf import settings

from .util import log_request


class TimeMiddleware(object):

    def process_request(self, request):
        request._time_start = datetime.datetime.now()
        return None

    def process_response(self, request, response):
        time_taken = datetime.datetime.now() - request._time_start
        limit = datetime.timedelta(
            milliseconds=settings.HANDLER_TIMEOUT_MILLIS)
        if time_taken > limit:
            log.warning('Took too long: %s' % time_taken)
            log_request(request)

        return response
