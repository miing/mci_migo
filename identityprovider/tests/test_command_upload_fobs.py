from StringIO import StringIO

from django.core.management import call_command
from django.test import TestCase

from mock import MagicMock, patch

from identityprovider.models import (
    Account,
    AuthenticationDevice,
    LPOpenIdIdentifier,
    Person,
)
from identityprovider.tests import DEFAULT_USER_PASSWORD


def mock_open(data):
    mock = MagicMock(spec=file)
    mock.write.return_value = None
    mock.__enter__.return_value = data
    return mock


test_username = 'test'
module = 'identityprovider.management.commands.upload_fobs'


class UploadFobsCommandTestCase(TestCase):

    def setUp(self):
        super(UploadFobsCommandTestCase, self).setUp()
        account = Account.objects.create_account(
            test_username, 'test@canonical.com', DEFAULT_USER_PASSWORD)
        p = Person.objects.create(name=test_username)
        p.lp_account = account.id
        p.save()
        lp = LPOpenIdIdentifier.objects.create(
            identifier=account.openid_identifier, lp_account=account.id)
        lp.save()

    def data(self, username=test_username):
        return dict(
            keys=StringIO('SN,key\n1,0123456789'),
            users=StringIO('SN,user\n1,' + username)
        )

    @patch(module + '.open', mock_open, create=True)
    def test_upload_csv(self):
        call_command('upload_fobs', **self.data())
        devices = AuthenticationDevice.objects.filter(key='0123456789')
        self.assertEqual(len(devices), 1)
        device = devices[0]
        self.assertIn('1', device.name)
        self.assertEqual(device.account.person.name, test_username)

    @patch(module + '.open', mock_open, create=True)
    @patch(module + '.logging.warn')
    def test_upload_invalid_email(self, mock_warn):
        assert AuthenticationDevice.objects.count() == 0
        call_command('upload_fobs', **self.data('notexist'))
        mock_warn.assert_called_once_with("User notexist not found")
        devices = AuthenticationDevice.objects.all()
        self.assertEqual(len(devices), 0)

    @patch(module + '.open', mock_open, create=True)
    @patch(module + '.logging.warn')
    def test_upload_invalid_account(self, mock_warn):
        assert AuthenticationDevice.objects.count() == 0
        person = Person.objects.get(name=test_username)
        person.lp_account = None
        person.save()
        call_command('upload_fobs', **self.data())
        mock_warn.assert_called_once_with(
            'Could not locate account for ' + test_username)
        devices = AuthenticationDevice.objects.all()
        self.assertEqual(len(devices), 0)

    @patch(module + '.open', mock_open, create=True)
    @patch(module + '.logging.warn')
    def test_upload_invalid_SN(self, mock_warn):
        assert AuthenticationDevice.objects.count() == 0
        call_command(
            'upload_fobs',
            keys=StringIO('SN,key\n1,0123456789'),
            users=StringIO('SN,user\n2,' + test_username))
        mock_warn.assert_called_once_with(
            'Fob SN 2 key not found')
        devices = AuthenticationDevice.objects.all()
        self.assertEqual(len(devices), 0)
