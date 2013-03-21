from unittest import TestCase

from mock import (
    Mock,
    patch,
)

from identityprovider.stats import stats


class StatsTestCase(TestCase):
    @patch('socket.gethostname')
    @patch('identityprovider.stats.Client.increment')
    def test_increment(self, mock_increment, mock_gethostname):
        mock_gethostname.return_value = 'localhost'
        stats.increment('foo')
        mock_increment.assert_called_with('localhost.sso.foo')

    @patch('socket.gethostname')
    @patch('identityprovider.stats.Client.increment')
    def test_increment_with_key(self, mock_increment, mock_gethostname):
        mock_gethostname.return_value = 'localhost'
        stats.increment('foo', key='bar')
        mock_increment.assert_called_with('localhost.sso.foo.bar')

    @patch('socket.gethostname')
    @patch('identityprovider.stats.Client.increment')
    def test_increment_with_rpconfig(self, mock_increment, mock_gethostname):
        mock_gethostname.return_value = 'localhost'
        rpconfig = Mock()
        rpconfig.trust_root = 'http://some.host/'
        stats.increment('foo', rpconfig=rpconfig)
        mock_increment.assert_called_with(
            'localhost.sso.foo.some-host')

    @patch('socket.gethostname')
    @patch('identityprovider.stats.Client.increment')
    def test_increment_with_invalid_trust_root(self, mock_increment,
                                               mock_gethostname):
        mock_gethostname.return_value = 'localhost'
        rpconfig = Mock()
        rpconfig.trust_root = 'some.host'
        stats.increment('foo', rpconfig=rpconfig)
        mock_increment.assert_called_with(
            'localhost.sso.foo')

    @patch('socket.gethostname')
    @patch('identityprovider.stats.Client.increment')
    def test_fully_qualified_stat(self, mock_increment, mock_gethostname):
        mock_gethostname.return_value = 'localhost.localdomain'
        stats.increment('foo')
        mock_increment.assert_called_with(
            'localhost_localdomain.sso.foo')
