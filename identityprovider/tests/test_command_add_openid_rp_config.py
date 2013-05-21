from django.core.management import call_command, CommandError
from django.test import TestCase

from identityprovider.models import OpenIDRPConfig
from identityprovider.utils import get_object_or_none


class AddOpenIDRPConfigCommandTestCase(TestCase):

    def test_add_without_root(self):
        with self.assertRaises(CommandError) as cm:
            call_command('add_openid_rp_config')
        self.assertEqual(str(cm.exception),
                         'Need to specify trust_root')

    def test_add_default(self):
        root = 'http://localhost:8000'
        call_command('add_openid_rp_config', root)
        config = get_object_or_none(OpenIDRPConfig, trust_root=root)
        self.assertIsNotNone(config)
        self.assertFalse(config.allow_unverified)
        self.assertEqual(config.allowed_user_attribs, '')

    def test_add_with_allow_unverified(self):
        root = 'http://localhost:8000'
        call_command('add_openid_rp_config', root, allow_unverified=True)
        config = get_object_or_none(OpenIDRPConfig, trust_root=root)
        self.assertIsNotNone(config)
        self.assertTrue(config.allow_unverified)

    def test_add_with_allowed_user_attribs_value(self):
        root = 'http://localhost:8000'
        call_command(
            'add_openid_rp_config', root,
            allowed_user_attribs='nickname,email')
        config = get_object_or_none(OpenIDRPConfig, trust_root=root)
        self.assertIsNotNone(config)
        self.assertFalse(config.allow_unverified)
        self.assertEqual(config.allowed_user_attribs, 'nickname,email')
