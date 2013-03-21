import re
import socket

from django.conf import settings

from pystatsd import Client


RE_TRUST_ROOT_HOSTNAME = re.compile(r'^http(s)?://(?P<hostname>[^/]*)/?')


class Stats(Client):
    def _get_fully_qualified_stat(self, name):
        hostname = socket.gethostname()
        return '{0}.sso.{1}'.format(hostname.replace('.', '_'), name)

    def _get_rpconfig_stat(self, name, rpconfig):
        match = RE_TRUST_ROOT_HOSTNAME.match(rpconfig.trust_root)
        if match is not None:
            hostname = match.groupdict()['hostname']
            name = '{0}.{1}'.format(name, hostname.replace('.', '-'))
        return name

    def _get_key_stat(self, name, key):
        return '{0}.{1}'.format(name, key)

    def increment(self, name, key=None, rpconfig=None):
        name = self._get_fully_qualified_stat(name)
        if rpconfig is not None:
            name = self._get_rpconfig_stat(name, rpconfig)
        if key is not None:
            name = self._get_key_stat(name, key)
        super(Stats, self).increment(name)


stats = Stats(settings.STATSD_HOST, settings.STATSD_PORT)
