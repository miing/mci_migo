# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import json
import os
import socket
import stat
import urllib
import urllib2

from time import time

from django.conf import settings
from django.db import connection, DEFAULT_DB_ALIAS

# When a request arrives, the middleware will:
# 1. check_readonly(), to reconcile our settings with the flagfiles.
#      Master DB recovery is attempted within this method call.
# 2. Iterating over (ReadOnlyManager.)connections, find the first connection
#      available for which is_failed() returns False.
#      This method just checks marker files, doesn't actually try to connect.
# 3. Call set_db() for that connection
# 4. Call ping_current_connection() to check if the connection is really live.
# 5. If ping_current_connection() returns False, call mark_failed() for that
#      connection (or mark_current_failed() which is just a shortcut)
#      and go back to step 2, until success or no connections left.
#      It will pass automatic=True into mark_failed, as this is the failover
#      code.

# Readonly commands and/or the readonly views will also use:
# - is_failed, next_recovery_due, to compile information to send
#   out in calls to /readonlydata and show in readonly --list.
# - connections, to iterate over all configured connections.
# - set_readonly, clear_readonly, mark_failed, clear_failed, to manage
#   the different readonly status information.  These views will always omit
#   automatic=True, as they manage manual overrides.


def _remote_req(host, port=None, scheme=None, server_id=None,
                virtual_host=None, post=None):
    """Makes a request to a specific appserver.

    The first five arguments are the same as the keys for each dictionary in
    the APP_SERVERS setting:

    * host: The host at which we can reach the app server (can be an IP)
    * port: The port that should be used (optional)
    * scheme: The scheme to use to contact this app server (http/https)
              (defaults to http)
    * server_id: Some canonical name for this app server (optional)
    * virtual_host: The virtual host that should be used, for app servers that
                    serve multiple sites (optional).

    If post is provided, it should be a sequence of 2-tuples that will be
    encoded in to POST data.
    """
    if post is None:
        post = []
    post.append(('secret', settings.READONLY_SECRET))
    post = urllib.urlencode(post)

    if scheme is None:
        scheme = 'http'
    if port is None:
        portstr = ''
    else:
        portstr = ':' + port
    url = '%s://%s%s/readonlydata' % (scheme, host, portstr)
    headers = {}
    if virtual_host is not None:
        headers['Host'] = virtual_host
    req = urllib2.Request(url, headers=headers, data=post)
    try:
        oldtimeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5)
        datafile = urllib2.urlopen(req)
        data = datafile.read()
        socket.setdefaulttimeout(oldtimeout)
    except urllib2.URLError:
        data = None
    return data


def lowercase_keys(dicts):
    """ Convert all keys in a list of dicts to lowercase. """
    return [dict((k.lower(), v) for (k, v) in d.items()) for d in dicts]


def get_server_atts(servers):
    """Provides a report about readonly status of all app servers."""
    appservers = []
    set_all_readonly = False
    clear_all_readonly = False
    for server in lowercase_keys(servers):
        datastr = _remote_req(**server)
        if datastr is None:
            data = {'reachable': False}
        else:
            try:
                data = json.loads(datastr)
            except ValueError:
                # This is probably caused by the remote database being out
                # of sync with our current database
                data = {'reachable': False}
            else:
                data['reachable'] = True
            if data.get('readonly'):
                clear_all_readonly = True
            else:
                set_all_readonly = True
        data['name'] = server['server_id']
        appservers.append(data)
    atts = {
        'appservers': appservers,
        'clear_all_readonly': clear_all_readonly,
        'set_all_readonly': set_all_readonly,
    }
    return atts


def update_server(action, appserver=None, conn=None):
    if appserver is None:
        appservers = settings.APP_SERVERS
    else:
        appservers = [server for server in settings.APP_SERVERS
                      if server['SERVER_ID'] == appserver]
    appservers = lowercase_keys(appservers)
    for server in appservers:
        post = [('action', action), ('conn', conn)]
        _remote_req(post=post, **server)


class ReadOnlyManager(object):
    @property
    def readonly_marker_file(self):
        flagdir = getattr(settings, 'DBFAILOVER_FLAG_DIR', '/tmp')
        return os.path.join(flagdir, 'db.readonly')

    @property
    def marker_file_pattern(self):
        flagdir = getattr(settings, 'DBFAILOVER_FLAG_DIR', '/tmp')
        return os.path.join(flagdir, 'db.%s.failed')

    def check_readonly(self):
        """Check readonly flag file and settings for consistency."""
        if os.path.exists(self.readonly_marker_file):
            settings.READ_ONLY_MODE = True
            if self.current_readonly_is_automatic():
                next_recovery_due = self.next_recovery_due()
                if next_recovery_due is not None and next_recovery_due < 0:
                    self.set_db(self.connections[0])
                    if self.ping_current_connection():
                        self.clear_failed(self.master_dbid())
                        self.clear_readonly()
                    else:
                        self.mark_failed(self.master_dbid(), automatic=True)
        else:
            settings.READ_ONLY_MODE = False
            if self.is_failed(self.master_dbid()):
                self.set_readonly(automatic=True)

    def set_readonly(self, automatic=False):
        """Create a marker file to indicate we're in readonly mode

        automatic means that this is part of automatic DB failover and
        will trigger automatic recovery.
        """
        settings.READ_ONLY_MODE = True
        attempts = 0
        if automatic:
            attempts = self.current_readonly_attempts() + 1
        self._readonly_markerfile_contents = {
            'automatic': automatic,
            'attempts': attempts,
        }

    def clear_readonly(self):
        """Clear the marker file to leave readonly mode."""
        settings.READ_ONLY_MODE = False
        if os.path.exists(self.readonly_marker_file):
            os.remove(self.readonly_marker_file)

    def set_db(self, db):
        """ Receives one item of settings.DB_CONNECTIONS, and uses that
            to set the database connection
        """
        for attname in ['HOST', 'PORT', 'NAME', 'USER', 'PASSWORD', 'ID']:
            attvalue = db.get(attname, '')
            # update new-style db settings (DATABASES['default'][xxx])
            settings.DATABASES[DEFAULT_DB_ALIAS][attname] = attvalue
            # need to update the DatabaseWrapper cached settings_dict
            # to keep up to date with the new db setting
            connection.settings_dict[attname] = attvalue

    def mark_current_failed(self, automatic=False):
        """Mark the current DB connection as failed.

        automatic means that this DB failover is automatic and
        will trigger automatic recovery.
        """
        self.mark_failed(self.current_dbid(), automatic=automatic)

    def mark_failed(self, dbname, automatic=False):
        """Create a marker file for the given dbname.

        If dbname is our master connection, also enter readonly mode.

        automatic means that this DB failover is automatic and
        will trigger automatic recovery.
        """
        filename = self.marker_file_pattern % dbname
        if not os.path.exists(filename):
            open(filename, 'a').close()
            mode = os.stat(filename)[stat.ST_MODE]
            os.chmod(filename, mode | stat.S_IRGRP | stat.S_IWGRP)
        if dbname == self.master_dbid():
            self.set_readonly(automatic=automatic)

    def clear_failed(self, dbname):
        """Remove failed marker file for the given dbname."""
        if self.is_failed(dbname):
            filename = self.marker_file_pattern % dbname
            os.remove(filename)

    def is_failed(self, dbname):
        """Returns true if a marker file exists for the given dbname."""
        filename = self.marker_file_pattern % dbname
        return os.path.exists(filename)

    def get_connections(self):
        return settings.DB_CONNECTIONS
    connections = property(get_connections)

    def current_dbid(self):
        """Return an id for the current database being used.

        If this is the first time we're being called, use the first
        connection listed in settings.DB_CONNECTIONS
        """
        db = settings.DATABASES[DEFAULT_DB_ALIAS]
        if not 'ID' in db:
            self.set_db(self.connections[0])
        return db['ID']

    def master_dbid(self):
        """Return the id for the master DD connection."""
        return self.connections[0]['ID']

    def next_recovery_due(self):
        """How many seconds are missing for next automatic recovery attempt.

        Assumes we're currently in readonly mode.

        Will return None if failure is considered permanent and manual
        intervention is needed.

        If result is < 0, recovery should be attempted immediately.
        """
        attempts = self.current_readonly_attempts()
        if not os.path.exists(self.readonly_marker_file):
            return None
        if attempts > settings.DBRECOVER_ATTEMPTS:
            return None
        else:
            return (os.stat(self.readonly_marker_file)[stat.ST_MTIME] +
                    settings.DBRECOVER_INTERVAL *
                    settings.DBRECOVER_MULTIPLIER ** attempts - time())

    def current_readonly_attempts(self):
        return self._readonly_markerfile_contents.get('attempts', 0)

    def current_readonly_is_automatic(self):
        return self._readonly_markerfile_contents.get('automatic')

    def _get_readonly_markerfile_contents(self):
        if not hasattr(self, '_cached_readonly_markerfile_contents'):
            if os.path.exists(self.readonly_marker_file):
                markerfile = open(self.readonly_marker_file)
                try:
                    data = json.loads(markerfile.read())
                except ValueError:
                    data = {'attempts': 1, 'automatic': True}
                markerfile.close()
            else:
                data = {}
            self._cached_readonly_markerfile_contents = data
        return self._cached_readonly_markerfile_contents

    def _set_readonly_markerfile_contents(self, data):
        flags = os.O_WRONLY | os.O_CREAT  # *not* os.O_TRUNC
        markerfd = os.open(self.readonly_marker_file, flags)
        os.write(markerfd, "%40s\n" % json.dumps(data))
        os.close(markerfd)
        mode = os.stat(self.readonly_marker_file)[stat.ST_MODE]
        group_perms = stat.S_IRGRP | stat.S_IWGRP
        if mode & group_perms != group_perms:
            os.chmod(self.readonly_marker_file, mode | group_perms)
        self._cached_readonly_markerfile_contents = data

    _readonly_markerfile_contents = property(
        _get_readonly_markerfile_contents,
        _set_readonly_markerfile_contents)

    def ping_current_connection(self):
        """Attempt to connect and query the current db"""
        result = False
        try:
            cursor = connection.cursor()
            cursor.execute('SELECT 42')
            result = True
        except Exception:
            # Just catch all exceptions here because the DB-API
            # doesn't define a standard set of exceptions to catch, so
            # we'd need to start catching engine-specific stuff.
            pass
        return result
