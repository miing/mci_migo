# Copyright 2011 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
import re
import os.path

from django.conf import settings


class ProfileMiddleware(object):

    def __init__(self):
        self.filename = getattr(settings, "PROFILE_FILENAME", "sso.profile")
        self.pattern = getattr(settings, "PROFILE_PATTERN",
                               "identityprovider\..*")
        self.regex = re.compile(self.pattern)

    def process_view(self, request, view_func, view_args, view_kwargs):
        from cProfile import Profile
        from pstats import Stats
        full_name = "{v.__module__}.{v.func_name}".format(v=view_func)
        if self.regex.match(full_name):
            profile = Profile()

            response = profile.runcall(view_func, request, *view_args,
                                       **view_kwargs)

            stats = Stats(profile)
            if os.path.exists(self.filename):
                stats.add(self.filename)
            stats.strip_dirs()
            stats.dump_stats(self.filename)

            return response
