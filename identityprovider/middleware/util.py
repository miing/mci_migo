# Copyright 2011 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import logging
import re
import sys
import traceback

from django.conf import settings
from django.db import connection
from django.views import debug


debug.HIDDEN_SETTINGS = re.compile(
    'SECRET|PASSWORD|PROFANITIES_LIST|PRIVATE|secret|password|private')


def _sanitize_dict(dirty):
    clean = dirty.copy()
    for key in dirty.iterkeys():
        if debug.HIDDEN_SETTINGS.search(key):
            clean[key] = '********'
    return clean


def _sanitize_request(request):
    """Remove sensitive information from the request before it is
    displayed."""
    request.GET = _sanitize_dict(request.GET)
    request.POST = _sanitize_dict(request.POST)
    return request


def _sanitize_vars(items):
    sanitized = []
    for item in items:
        if debug.HIDDEN_SETTINGS.search(item[0]):
            sanitized.append((item[0], '********'))
        else:
            sanitized.append(item)
    return sanitized


class _ExceptionReporter(debug.ExceptionReporter):

    # This function was taken from the django project.
    # Please see the license file in the third-party/django directory.
    def get_traceback_frames(self):
        frames = []
        tb = sys.exc_info()[2]
        while tb is not None:
            # support for __traceback_hide__ which is used by a few libraries
            # to hide internal frames.
            if tb.tb_frame.f_locals.get('__traceback_hide__'):
                tb = tb.tb_next
                continue
            filename = tb.tb_frame.f_code.co_filename
            function = tb.tb_frame.f_code.co_name
            lineno = tb.tb_lineno - 1
            loader = tb.tb_frame.f_globals.get('__loader__')
            module_name = tb.tb_frame.f_globals.get('__name__')
            res = self._get_lines_from_file(filename, lineno, 7, loader,
                                            module_name)
            pre_context_lineno, pre_context, context_line, post_context = res
            if pre_context_lineno is not None:
                frames.append({
                    'tb': tb,
                    'filename': filename,
                    'function': function,
                    'lineno': lineno + 1,
                    'vars': _sanitize_vars(tb.tb_frame.f_locals.items()),
                    'id': id(tb),
                    'pre_context': pre_context,
                    'context_line': context_line,
                    'post_context': post_context,
                    'pre_context_lineno': pre_context_lineno + 1,
                })
            tb = tb.tb_next

        if not frames:
            frames = [{
                'filename': '&lt;unknown&gt;',
                'function': '?',
                'lineno': '?',
                'context_line': '???',
            }]

        return frames


def log_request(request, log_exception_trace=False):
    """Log the request, so that it can be kept in the oops file"""
    request = _sanitize_request(request)
    reporter = _ExceptionReporter(request, *sys.exc_info())

    template_debug = settings.TEMPLATE_DEBUG
    settings.TEMPLATE_DEBUG = True
    try:
        logging.warn(reporter.get_traceback_html())
        if log_exception_trace:
            logging.warn(traceback.format_exc())
        for query in connection.queries:
            logging.warn("time: %(time)s sql: %(sql)s" % query)
    finally:
        settings.TEMPLATE_DEBUG = template_debug
