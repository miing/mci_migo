# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import string

from datetime import datetime
from urllib import quote as urlquote
from base64 import b32encode

from django.core.urlresolvers import reverse
from django.conf import settings
from django.http import Http404
from django.test import TestCase

from gargoyle.testutils import switches
from pyquery import PyQuery
from mock import (
    MagicMock,
    call,
    patch,
)

from identityprovider.models import (
    AuthenticationDevice,
    EmailAddress,
    twofactor,
)
from identityprovider.utils import add_user_to_team
from identityprovider.tests.utils import (
    AuthenticatedTestCase,
    SSOBaseTestCase,
    patch_settings,
)
from webui.views.devices import (
    DEVICE_DELETED,
    DEVICE_GENERATION_WARNING,
    device_addition,
    device_generate,
    device_list,
    device_print,
    device_removal,
    get_unique_device_name_for_user,
)


MOD_PREFIX = 'webui.views.devices'
IS_UPGRADED = 'webui.decorators.twofactor.is_upgraded'


class TwoFactorMixin(object):

    class device(object):
        def __init__(self, name='My device name', id=33):
            self.name = name
            self.id = id

    def setUp(self):
        super(TwoFactorMixin, self).setUp()
        self.switch = switches(TWOFACTOR=True)
        self.switch.patch()
        self.addCleanup(self.switch.unpatch)

    def _get_mock_request(self, twofactor_required=False, devices=None):
        devices = devices or []
        mock_request = MagicMock()
        mock_request.user.is_authenticated.return_value = True
        mock_request.user.preferredemail.email = 'user@somedomain.com'
        mock_request.user.twofactor_required = twofactor_required
        mock_request.method = 'GET'
        mock_request.POST = {}
        mock_request.META = {}
        mock_request.user.devices.all.return_value = devices
        return mock_request


class TestDeviceList(TwoFactorMixin, TestCase):

    def test_device_list_no_devices(self):
        mock_request = self._get_mock_request()
        response = device_list(mock_request)
        self.assertEqual(response.status_code, 200)

        tree = PyQuery(response.content)

        devices = tree.find('table#device-list')
        self.assertEqual(devices, [])

    def test_device_list_one_device(self):
        mock_request = self._get_mock_request(
            twofactor_required=True, devices=[self.device])
        response = device_list(mock_request)
        self.assertEqual(response.status_code, 200)

        tree = PyQuery(response.content)

        rows = tree.find('table#device-list').find('tbody tr')
        self.assertEqual(len(rows), 1)
        name, command = rows.find('td')
        links = command.findall('a')
        self.assertEqual(len(links), 2)
        self.assertEqual(links[1].get('href'), "/device-removal/33")
        self.assertEqual(name.text, 'My device name')


class DeviceTemplateTest(AuthenticatedTestCase):

    def setUp(self):
        super(DeviceTemplateTest, self).setUp()
        condition_set = 'identityprovider.gargoyle.LPTeamConditionSet(lp_team)'
        self.conditionally_enable_flag(
            'PAPER_DEVICE', 'team', 'paperdeviceteam', condition_set)

        # enable TWOFACTOR flag
        twofactor_switch = switches(TWOFACTOR=True)
        twofactor_switch.patch()
        self.addCleanup(twofactor_switch.unpatch)

    def get_device_types(self):
        response = self.client.get(reverse('device-addition'))
        self.assertEqual(response.status_code, 200)

        tree = PyQuery(response.content)
        nodes = tree.find('input[type="radio"]')

        device_types = [dict(node.items())['value'] for node in nodes]
        return device_types

    def test_paper_device_flag_in_template_user_in_team(self):
        email = EmailAddress.objects.get(email=self.login_email)
        add_user_to_team(email.account, 'paperdeviceteam')

        device_types = self.get_device_types()
        self.assertIn('paper', device_types)

    def test_paper_device_flag_in_template_user_not_in_team(self):
        device_types = self.get_device_types()
        self.assertNotIn('paper', device_types)


class TestDeviceAddition(TwoFactorMixin, TestCase):

    # This is the example OATH/HOTP key from RFC 4226:
    # http://www.ietf.org/rfc/rfc4226.txt
    KEY = '3132333435363738393031323334353637383930'
    BASIC_TYPES = ['google', 'yubi', 'generic']
    DEFAULT_ID = 256

    def test_device_types(self):
        self.assert_device_types(paper_flag=False,
                                 expected_types=self.BASIC_TYPES)

    def test_device_types_with_paper_enabled(self):
        self.assert_device_types(paper_flag=True,
                                 expected_types=self.BASIC_TYPES + ['paper'])

    def assert_device_types(self, paper_flag, expected_types):
        request = self._get_mock_request()

        with switches(PAPER_DEVICE=paper_flag):
            response = device_addition(request)

        tree = PyQuery(response.content)
        type_nodes = tree.find('input[type="radio"]')

        # Note: can't just use node.value as it is None for unset radios
        self.assertEqual([dict(node.items())['value'] for node in type_nodes],
                         expected_types)

    def _get_post_request(self, **post_data):
        mock_request = self._get_mock_request()
        mock_request.method = 'POST'
        mock_request.POST.update(post_data)
        mock_request.session = {twofactor.TWOFACTOR_LOGIN: datetime.utcnow()}
        return mock_request

    def _post_device_addition(self, mock_request):
        DEVICE_CLASS = '%s.AuthenticationDevice' % MOD_PREFIX
        GENERATE_KEY_FUNC = '%s.generate_key' % MOD_PREFIX
        with patch(DEVICE_CLASS) as MockDevice:
            MockDevice.objects.create.return_value.id = self.DEFAULT_ID
            with patch(GENERATE_KEY_FUNC) as mock_generate:
                mock_generate.return_value = self.KEY
                response = device_addition(mock_request)

        return response, MockDevice

    def test_initial_post(self):
        mock_request = self._get_post_request(type='generic')
        response, MockDevice = self._post_device_addition(mock_request)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(MockDevice.objects.create.called)

        tree = PyQuery(response.content)
        self.assertEqual(len(tree.find('.error')), 0)
        device_name = tree.find('input[type=text][name=name]')
        self.assertEqual(len(device_name), 1)
        self.assertEqual(device_name.val(), 'Authentication device')

    def test_initial_post_google(self):
        mock_request = self._get_post_request(type='google')
        email = 'email@example.com'
        mock_request.user.preferredemail.email = email
        response, MockDevice = self._post_device_addition(mock_request)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(MockDevice.objects.create.called)

        tree = PyQuery(response.content)
        self.assertEqual(len(tree.find('.error')), 0)
        device_name = tree.find('input[type=text][name=name]')
        self.assertEqual(len(device_name), 1)
        self.assertEqual(device_name.val(), 'Google Authenticator')

        qrcode = tree.find('img.qrcode')
        self.assertEqual(len(qrcode), 1)
        url = qrcode[0].attrib['src']
        # correct https domain
        self.assertIn('https://chart.googleapis.com', url)
        self.assertIn(urlquote(email), url)
        self.assertIn(b32encode(self.KEY.decode('hex')), url)

    def test_initial_post_yubikey(self):
        mock_request = self._get_post_request(type='yubi')
        response, MockDevice = self._post_device_addition(mock_request)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(MockDevice.objects.create.called)

        tree = PyQuery(response.content)

        formatted_keys = tree.find('#formatted_key')
        self.assertEqual(len(formatted_keys), 1)
        formatted_key = formatted_keys[0].text.strip()
        self.assertEqual(formatted_key.replace(' ', ''), self.KEY)

        for key_id in ('short_press', 'long_press'):
            nodes = tree.find('#%s' % key_id)
            self.assertEqual(len(nodes), 1)
            command = nodes[0].text.strip()
            self.assertTrue(self.KEY.lower() in command)

    def test_successful_post(self):
        mock_request = self._get_post_request(
            type='generic',
            name='Some device',
            otp='755224',
            hex_key=self.KEY
        )
        self.assert_successful_post(mock_request, 'Some device', 1, 'generic')

    def test_successful_post_paper(self):
        mock_request = self._get_post_request(type='paper')

        name = 'Printable Backup Codes'
        counter = 0
        redirect_to = '/device-print/' + str(self.DEFAULT_ID)
        self.assert_successful_post(mock_request, name, counter, 'paper',
                                    redirect_to)

    def assert_successful_post(self, mock_request, name, counter, device_type,
                               redirect_to='/device-list'):
        mock_request.session = {}
        mock_request.user.has_twofactor_devices.return_value = False

        DATETIME_PATH = 'identityprovider.models.twofactor.datetime'
        with patch(DATETIME_PATH) as mock_datetime:
            mock_datetime.utcnow.return_value = datetime(2012, 04, 01)
            response, MockDevice = self._post_device_addition(mock_request)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response['Location'], redirect_to)

        MockDevice.objects.create.assert_called_once_with(
            name=name,
            key=self.KEY,
            account=mock_request.user,
            counter=counter,
            device_type=device_type
        )
        self.assertEqual(mock_request.session[twofactor.TWOFACTOR_LOGIN],
                         mock_datetime.utcnow.return_value)

    def test_unrecognised_type(self):
        mock_request = self._get_post_request(
            type='foobar',
            hex_key=self.KEY,
            name='Some device',
            otp='some otp key',
        )
        response, MockDevice = self._post_device_addition(mock_request)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(MockDevice.objects.create.called)

        tree = PyQuery(response.content)
        input_type = tree.find('input[type=radio][name=type][value=generic]')
        self.assertEqual(len(input_type), 1)

    def test_errors(self):
        mock_request = self._get_post_request(
            type='generic',
            hex_key=self.KEY,
            name='',
            otp='',
        )
        response, MockDevice = self._post_device_addition(mock_request)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(MockDevice.objects.create.called)

        tree = PyQuery(response.content)
        self.assertEqual(len(tree.find('.error')), 2)

    def test_add_second_device_unathenticated(self):
        mock_request = self._get_post_request(
            type='generic',
            name='Some device',
            otp='755224',
            hex_key=self.KEY,
        )
        mock_request.user.has_twofactor_devices.return_value = True
        with patch(IS_UPGRADED) as mock_is_upgraded:
            mock_is_upgraded.return_value = False
            response, MockDevice = self._post_device_addition(mock_request)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response['Location'].startswith('/two_factor_auth?next='))

    def test_add_second_device_athenticated(self):
        mock_request = self._get_post_request(
            type='generic',
            name='Some device',
            otp='755224',
            hex_key=self.KEY,
        )
        mock_request.user.has_twofactor_devices.return_value = True
        with patch(IS_UPGRADED) as mock_is_upgraded:
            mock_is_upgraded.return_value = True
            response, MockDevice = self._post_device_addition(mock_request)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response['Location'], '/device-list')

        MockDevice.objects.create.assert_called_once_with(
            name='Some device',
            key=self.KEY,
            account=mock_request.user,
            counter=1,
            device_type='generic'
        )


class TestPaperPrintingAndGenerating(TwoFactorMixin, SSOBaseTestCase):

    letters = list(string.ascii_letters) * 3

    def _do_patch(self, name):
        p = patch(name)
        mock_obj = p.start()
        self.addCleanup(p.stop)
        return mock_obj

    def _get_response_doc(self, response):
        # handle TemplateResponse et al, as django does
        if hasattr(response, 'render'):
            response.render()
        return PyQuery(response.content)

    def setUp(self):
        super(TestPaperPrintingAndGenerating, self).setUp()

        switch = switches(PAPER_DEVICE=True)
        switch.patch()
        self.addCleanup(switch.unpatch)

        self.device = MagicMock(autospec=AuthenticationDevice)
        self.device.id = 1
        self.device.key = 'some key'
        self.device.counter = 0
        self.device.device_type = 'paper'

        mock_get = self._do_patch(MOD_PREFIX + '._get_device_or_404')
        mock_get.return_value = self.device

        self.mock_hotp = mock_hotp = self._do_patch(MOD_PREFIX + '.hotp')
        mock_hotp.side_effect = lambda k, i, t: self.letters[i]

        p = patch_settings(TWOFACTOR_PAPER_CODES=10)
        p.start()
        self.addCleanup(p.stop)

        self.mock_request = self._get_mock_request()
        self.mock_request.user = self.factory.make_account()

    def print_with_counter(self, counter):
        self.device.counter = counter
        offset, position = divmod(counter, settings.TWOFACTOR_PAPER_CODES)
        offset *= settings.TWOFACTOR_PAPER_CODES

        response = device_print(self.mock_request, self.device.id)

        doc = self._get_response_doc(response)
        code_nodes = doc.find('#codes li')
        used = code_nodes[:position]
        unused = code_nodes[position:]

        self.assertEqual(len(used), position)
        self.assertEqual(len(unused),
                         settings.TWOFACTOR_PAPER_CODES - position)

        # check the first N are rendered with strike-through
        for elem, letter in zip(used, self.letters[offset:]):
            strike = elem.findall('strike')
            self.assertEqual(len(strike), 1)
            self.assertEqual(strike[0].text.strip(), letter)

        # check the next N are not
        for elem, letter in zip(unused, self.letters[counter:]):
            strike = elem.findall('strike')
            self.assertEqual(len(strike), 0)
            self.assertEqual(elem.text.strip(), letter)

    def test_print_codes_new_and_unused(self):
        self.print_with_counter(0)

    def test_print_codes_window_0(self):
        self.print_with_counter(5)

    def test_print_codes_window_1(self):
        self.print_with_counter(13)

    def test_print_codes_window_2(self):
        self.print_with_counter(27)

    def test_print_codes_window_boundry(self):
        self.print_with_counter(settings.TWOFACTOR_PAPER_CODES - 1)
        self.print_with_counter(settings.TWOFACTOR_PAPER_CODES)

    def test_non_paper_404(self):
        device = self.device
        device.device_type = 'generic'
        with self.assertRaises(Http404):
            device_print(self.mock_request, device.id)

    def test_device_generate_get(self):
        self.device.counter = settings.TWOFACTOR_PAPER_CODES * 3 + 6
        response = device_generate(self.mock_request, self.device.id)

        doc = self._get_response_doc(response)
        code_nodes = doc.find('#codes li')

        start = settings.TWOFACTOR_PAPER_CODES * 4
        end = settings.TWOFACTOR_PAPER_CODES * 5
        expected_calls = [call('some key', i, 'dec6')
                          for i in range(start, end)]
        self.assertEqual(self.mock_hotp.mock_calls, expected_calls)
        codes = [node.text.strip() for node in code_nodes]
        self.assertEqual(codes, self.letters[start:end])

    def test_device_generate_post_saves_and_redirects(self):
        device = self.device
        # with no addition this time - testing the edge case
        device.counter = settings.TWOFACTOR_PAPER_CODES * 3
        self.mock_request.method = 'POST'

        response = device_generate(self.mock_request, self.device.id)
        self.assertEqual(response.status_code, 302)
        expected_redirect = '/device-print/%s' % self.device.id
        self.assertEqual(response['location'], expected_redirect)

        device.save.assert_called_once_with()
        self.assertEqual(device.counter, settings.TWOFACTOR_PAPER_CODES * 4)

    def test_device_generate_not_paper(self):
        device = self.device
        device.device_type = 'generic'
        with self.assertRaises(Http404):
            device_generate(self.mock_request, device.id)

    def test_device_generate_not_available_if_enough_remaining_codes(self):
        allow_generation = settings.TWOFACTOR_PAPER_CODES - 1
        with patch_settings(
                TWOFACTOR_PAPER_CODES_ALLOW_GENERATION=allow_generation):
            self.device.counter = (
                settings.TWOFACTOR_PAPER_CODES -
                settings.TWOFACTOR_PAPER_CODES_ALLOW_GENERATION) - 1

            response = device_print(self.mock_request, self.device.id)
            doc = self._get_response_doc(response)
            generate_url = '/device-generate/%s' % self.device.id
            generate_button = doc.find('a.btn[href="%s"]' % generate_url)
            self.assertEqual(len(generate_button), 0)
            self.assertFalse(response.context_data['generation_enabled'])

    def assert_generation_warning_and_button(self, counter):
        self.device.counter = counter

        with patch(MOD_PREFIX + '.messages') as mock_messages:
            response = device_print(self.mock_request, self.device.id)

        doc = self._get_response_doc(response)
        # check generate button is available
        generate_url = '/device-generate/%s' % self.device.id
        generate_button = doc.find('a[href="%s"]' % generate_url)
        self.assertEqual(len(generate_button), 1)
        self.assertTrue(response.context_data['generation_enabled'])
        # check warning message is set
        mock_messages.warning.assert_called_once_with(
            self.mock_request, DEVICE_GENERATION_WARNING)

    def test_device_generate_available_if_few_remaining_codes(self):
        for i in range(settings.TWOFACTOR_PAPER_CODES_ALLOW_GENERATION):
            counter = (settings.TWOFACTOR_PAPER_CODES -
                       settings.TWOFACTOR_PAPER_CODES_ALLOW_GENERATION) + i
            self.assert_generation_warning_and_button(counter)


class TestDeviceRemoval(TwoFactorMixin, SSOBaseTestCase):

    def _get_account(self):
        return self._factory.make_account()

    def test_device_not_found(self):
        mock_request = self._get_mock_request()
        mock_request.user = self.factory.make_account()
        self.assertRaises(Http404, device_removal, mock_request, 23)

    def test_device_owned_by_another_user(self):
        account1 = self.factory.make_account()
        account2 = self.factory.make_account()

        mock_request = self._get_mock_request()
        mock_request.user = account1

        device = AuthenticationDevice.objects.create(
            account=account2,
            key='some key',
            name='Some device'
        )
        self.assertRaises(Http404, device_removal, mock_request, device.id)

    def test_get(self):
        account = self.factory.make_account()
        mock_request = self._get_mock_request()
        mock_request.user = account

        device = AuthenticationDevice.objects.create(
            account=account,
            key='some key',
            name='Some device'
        )

        response = device_removal(mock_request, device.id)
        self.assertEqual(response.status_code, 200)

        # check that a GET does not delete the device
        AuthenticationDevice.objects.get(id=device.id)

        tree = PyQuery(response.content)
        self.assertEqual(tree.find(
            '[data-qa-id="device_removal_device_name"]').text(), "Some device")

    def test_post(self):
        account = self.factory.make_account()
        mock_request = self._get_mock_request()
        mock_request.user = account
        mock_request.method = 'POST'

        device = AuthenticationDevice.objects.create(
            account=account,
            key='some key',
            name='Some device'
        )

        response = device_removal(mock_request, device.id)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response['Location'], '/device-list')

        self.assertEqual(AuthenticationDevice.objects.all().count(), 0)

    def test_preference_reset(self):
        account = self.factory.make_account()
        account.twofactor_required = True
        mock_request = self._get_mock_request()
        mock_request.user = account
        mock_request.method = 'POST'

        device1 = AuthenticationDevice.objects.create(
            account=account,
            key='some key',
            name='First device'
        )
        device2 = AuthenticationDevice.objects.create(
            account=account,
            key='some key',
            name='Second device'
        )

        device_removal(mock_request, device1.id)
        self.assertTrue(account.twofactor_required)

        device_removal(mock_request, device2.id)
        self.assertFalse(account.twofactor_required)

    def test_device_removal_requires_two_factor_auth(self):
        mock_request = self._get_mock_request()

        with patch(IS_UPGRADED) as mock_is_authenticated:
            mock_is_authenticated.return_value = False
            response = device_removal(mock_request, 199)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response['Location'].startswith('/two_factor_auth?next='))

    def test_last_device_removal_un_authenticates(self):
        mock_request = self._get_mock_request()
        mock_request.user = self.factory.make_account()
        mock_request.method = 'POST'
        mock_request.session = {twofactor.TWOFACTOR_LOGIN: datetime.utcnow()}
        mock_request.user.has_twofactor_devices = MagicMock()
        mock_request.user.has_twofactor_devices.return_value = False

        with patch(MOD_PREFIX + '.get_object_or_404') as mock_device:
            with patch(MOD_PREFIX + '.messages') as mock_messages:
                mock_device.return_value.name = 'foo'
                device_removal(mock_request, 100)

        mock_messages.success.assert_called_once_with(
            mock_request, DEVICE_DELETED.format(name='foo'))


class TestUtils(TwoFactorMixin, TestCase):

    def _get_mock_user(self, devices):
        mock_user = MagicMock()
        mock_user.devices.all.return_value = devices
        return mock_user

    def test_name_with_empty_existing(self):
        user = self._get_mock_user([])
        result = get_unique_device_name_for_user('test', user)
        self.assertEqual(result, 'test')

    def test_name_with_existing_unmatched(self):
        user = self._get_mock_user([self.device('some other name')])
        result = get_unique_device_name_for_user('test', user)
        self.assertEqual(result, 'test')

    def test_name_with_existing_matched(self):
        user = self._get_mock_user([self.device('test'),
                                    self.device('test (1)')])
        result = get_unique_device_name_for_user('test', user)
        self.assertEqual(result, 'test (2)')
