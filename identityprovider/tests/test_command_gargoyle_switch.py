from distutils.version import StrictVersion
from unittest import skipIf
from django.test import TestCase
from django.core.management import call_command
from django.core.management.base import CommandError
from gargoyle import VERSION as GARGOYLE_VERSION
from gargoyle.models import (
    DISABLED,
    GLOBAL,
    Switch,
)
from gargoyle.manager import SwitchManager
from identityprovider.management.commands.add_switch import (
    Command as AddSwitchCmd,
)
from identityprovider.management.commands.remove_switch import (
    Command as RemoveSwitchCmd
)


class CommandAddSwitchTestCase(TestCase):

    def setUp(self):
        super(CommandAddSwitchTestCase, self).setUp()
        self.gargoyle = SwitchManager(Switch, key='key', value='value',
                                      instances=True, auto_create=True)

    @skipIf(GARGOYLE_VERSION == 'unknown', 'Unknown gargoyle version.')
    def test_version(self):
        if StrictVersion(GARGOYLE_VERSION) > StrictVersion('0.10.6'):
            self.fail('Switch to use the upstream implementation in '
                      'gargoyle itself.')

    def test_requires_single_arg(self):
        too_few_too_many = [
            [],
            ['one', 'two'],
        ]
        for args in too_few_too_many:
            command = AddSwitchCmd()

            self.assertRaises(CommandError, command.handle, *args)

    def test_add_switch_default_status(self):
        self.assertNotIn('switch_default', self.gargoyle)

        call_command('add_switch', 'switch_default')

        self.assertIn('switch_default', self.gargoyle)
        self.assertEqual(GLOBAL, self.gargoyle['switch_default'].status)

    def test_add_switch_with_status(self):
        self.assertNotIn('switch_disabled', self.gargoyle)

        call_command('add_switch', 'switch_disabled', status=DISABLED)

        self.assertIn('switch_disabled', self.gargoyle)
        self.assertEqual(DISABLED, self.gargoyle['switch_disabled'].status)

    def test_update_switch_status_disabled(self):
        Switch.objects.create(key='test', status=GLOBAL)
        self.assertEqual(GLOBAL, self.gargoyle['test'].status)

        call_command('add_switch', 'test', status=DISABLED)

        self.assertEqual(DISABLED, self.gargoyle['test'].status)

    def test_update_switch_status_to_default(self):
        Switch.objects.create(key='test', status=DISABLED)
        self.assertEqual(DISABLED, self.gargoyle['test'].status)

        call_command('add_switch', 'test')

        self.assertEqual(GLOBAL, self.gargoyle['test'].status)


class CommandRemoveSwitchTestCase(TestCase):

    def setUp(self):
        super(CommandRemoveSwitchTestCase, self).setUp()
        self.gargoyle = SwitchManager(Switch, key='key', value='value',
                                      instances=True, auto_create=True)

    def test_requires_single_arg(self):
        too_few_too_many = [
            [],
            ['one', 'two'],
        ]
        for args in too_few_too_many:
            command = RemoveSwitchCmd()

            self.assertRaises(CommandError, command.handle, *args)

    def test_removes_switch(self):
        Switch.objects.create(key='test')
        self.assertIn('test', self.gargoyle)

        call_command('remove_switch', 'test')

        self.assertNotIn('test', self.gargoyle)

    def test_remove_non_switch_doesnt_error(self):
        self.assertNotIn('idontexist', self.gargoyle)

        call_command('remove_switch', 'idontexist')

        self.assertNotIn('idontexist', self.gargoyle)
