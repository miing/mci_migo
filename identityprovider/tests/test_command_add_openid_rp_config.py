from StringIO import StringIO

from django.core.management import call_command
from django.test import TestCase

from mock import patch

from identityprovider.models import OpenIDRPConfig
from identityprovider.utils import get_object_or_none


class AddOpenIDRPConfigCommandTestCase(TestCase):

    @patch('sys.exit')
    def test_add_without_root(self, mock_sys_exit):
        stderr = StringIO()
        call_command('add_openid_rp_config', stderr=stderr)
        mock_sys_exit.assert_called_once_with(1)
        stderr.seek(0)
        output = stderr.read()
        self.assertIn('Error: Need to specify trust_root', output)

    def test_add_default(self):
        root = 'http://localhost:8000'
        call_command('add_openid_rp_config', root)
        config = get_object_or_none(OpenIDRPConfig, trust_root=root)
        self.assertIsNotNone(config)
        self.assertFalse(config.allow_unverified)
        self.assertEqual(config.allowed_sreg, '')

    def test_add_with_allow_unverified(self):
        root = 'http://localhost:8000'
        call_command('add_openid_rp_config', root, allow_unverified=True)
        config = get_object_or_none(OpenIDRPConfig, trust_root=root)
        self.assertIsNotNone(config)
        self.assertTrue(config.allow_unverified)

    def test_add_with_sreg_value(self):
        root = 'http://localhost:8000'
        call_command(
            'add_openid_rp_config', root, allowed_sreg='nickname,email')
        config = get_object_or_none(OpenIDRPConfig, trust_root=root)
        self.assertIsNotNone(config)
        self.assertFalse(config.allow_unverified)
        self.assertEqual(config.allowed_sreg, 'nickname,email')

    def test_add_with_ax_value(self):
        root = 'http://localhost:8000'
        call_command(
            'add_openid_rp_config', root, allowed_ax='nickname,email')
        config = get_object_or_none(OpenIDRPConfig, trust_root=root)
        self.assertIsNotNone(config)
        self.assertFalse(config.allow_unverified)
        self.assertEqual(config.allowed_ax, 'nickname,email')

    def test_add_with_ax_and_sreg_value(self):
        root = 'http://localhost:8000'
        call_command(
            'add_openid_rp_config', root, allowed_sreg='nickname',
            allowed_ax='nickname,email')
        config = get_object_or_none(OpenIDRPConfig, trust_root=root)
        self.assertIsNotNone(config)
        self.assertFalse(config.allow_unverified)
        self.assertEqual(config.allowed_sreg, 'nickname')
        self.assertEqual(config.allowed_ax, 'nickname,email')
