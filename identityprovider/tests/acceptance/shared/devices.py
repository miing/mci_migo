import re
from base64 import b32decode
from urlparse import urlparse, parse_qs

from oath import hotp

from sst import config
from sst.actions import (
    add_cleanup,
    assert_element,
    assert_url,
    click_button,
    click_link,
    exists_element,
    fails,
    get_current_url,
    get_element,
    get_elements,
    get_elements_by_css,
    go_to,
    set_radio_value,
    write_textfield,
)

from identityprovider.tests.acceptance.shared import urls


class Device(object):
    def __init__(self, name, aes_key=None, counter=None, codes=None):
        self.name = name
        self.aes_key = aes_key
        self.counter = counter
        if isinstance(codes, basestring):
            codes = [codes]
        self.codes = codes


def authenticate(name=None):
    cache = _get_device_cache()
    if name is None:
        # Just pick the first device we find
        name = cache.keys()[0]
    device = cache[name]

    if device.codes is None:
        otp = hotp.hotp(device.aes_key, device.counter)
        device.counter += 1
    else:
        otp = device.codes.pop(0)

    write_textfield('id_oath_token', otp)
    click_button(get_element(type='submit'))


def _get_device_cache():
    return config.cache.setdefault('devices', {})


def store_device(name, aes_key, counter=1):
    """Save a device in the device cache for use later."""
    cache = _get_device_cache()
    cache[name] = Device(name, aes_key, counter)


def store_paper_device(name, counter=0):
    """
    Must be called from the paper device-list page with a single paper device.
    """
    codes = _get_paper_device_codes(counter)
    cache = _get_device_cache()
    cache[name] = Device(name, codes=codes)


def _get_paper_device_codes(counter):
    url = get_current_url()
    restore = False
    if not re.match(r'.*/device-print/\d+$', url):
        assert_url('/device-list')
        click_link(get_element(tag='a', text='View Codes'))
        restore = True

    codes = [e.text for e in
             get_elements_by_css('ol.codelist li')][counter:]
    if restore:
        go_to('/device-list')
    return codes


def update_paper_device(name, counter=0):
    """Update codes for an existing device after generating new codes."""
    codes = _get_paper_device_codes(counter)
    cache = _get_device_cache()
    device = cache[name]
    device.codes = codes


def remove_device(name):
    """The opposite of store_device."""
    # Remove the device from the cache - if it is in there
    _get_device_cache().pop(name, None)


def click_add_device_button():
    click_button(get_element(tag='button', text_regex='Add device'))


def click_add_new_device_link():
    click_link(
        get_element(tag='a', text_regex='^Add a new authentication device'))


def click_delete_button():
    """Remove the first device in the list by clicking the delete button."""
    # Clicks the first Delete button it finds
    # this button is actually a link
    click_link(get_elements(tag='a', text_regex='Delete')[0])


def assert_device(name):
    assert_element(tag="td", text=name)


def assert_no_device(name):
    fails(get_element, tag="td", text=name)


def add_device(name='My device'):
    # Go to the authentication devices page
    go_to(urls.DEVICES)
    # Click on "Add a new authentication device" link
    click_add_new_device_link()
    # Choose "Generic HOTP device" and click add device
    set_radio_value('type_generic')
    click_add_device_button()

    # Add correctly generated OTP key
    aes_key = get_element(name='hex_key').get_attribute('value')
    valid_otp = hotp.hotp(aes_key, 0)
    write_textfield(get_element(tag='input', name='otp'), valid_otp)
    # Add a name
    write_textfield(get_element(tag='input', name='name'), name)
    # Click "Add device"
    click_add_device_button()
    store_device(name, aes_key)
    return aes_key


def delete_device():
    go_to(urls.DEVICES)
    # Fetch the name of the device we will be deleting
    name = get_elements_by_css('#device-list td.name')[0].text
    # Click on the delete button
    click_delete_button()

    # if we need to 2F auth this action
    if exists_element(id='id_oath_token'):
        authenticate()

    # Click on ok
    click_button(get_element(tag='button', text='Delete this device'))
    remove_device(name)

    # Check we are back on the device-list page
    assert_url('/device-list')
    # Check that our device has been deleted
    fails(get_element, 'device-list')


def rename_device(name, new_name):
    click_link(get_element(tag='a', text_regex='Rename'))
    # find name textfield
    elem = get_element(tag='input', name='name', value=name)
    # and update it
    write_textfield(elem, new_name)
    # and submit the form
    click_button(get_element(tag='button', text='Rename'))


def enter_otp(otp):
    write_textfield('id_oath_token', otp)
    click_button(get_element(type='submit'))


def add_device_cleanup():

    def cleanup():
        go_to(urls.DEVICES)
        # cleanup assumes the user is logged in, otherwise we get a circular
        # dependency between helpers and devices
        msg = 'Can not cleanup devices if user is not logged in.'
        assert '+login' not in get_current_url(), msg
        while get_elements_by_css('#device-list td.name'):
            name = get_elements_by_css('#device-list td.name')[0].text
            print 'Deleting a device:', name
            delete_device()

    add_cleanup(cleanup)


def get_key_from_qrcode(email):
    img = get_element(tag='img', css_class='qrcode')
    src = img.get_attribute('src')

    # check the url is well formed
    url = urlparse(src)
    assert url.scheme == 'https', "incorrect google charts protocol"
    msg = "incorrect google charts domain"
    assert url.netloc == 'chart.googleapis.com', msg
    qs = parse_qs(url.query)['chl'][0]
    otpauth = urlparse(qs)
    assert email in otpauth.path
    # python2.7.3 on quantal has a backport from 2.7 trunk (presumably will be
    # 2.7.4) and now urlparse correctly handles query string on *all* url types
    if otpauth.query:
        # urlparse has handled query string
        query = otpauth.query
    else:
        # we need to handle query string parsing
        query = otpauth.path.split('?')[1]
    b32_key = parse_qs(query)['secret'][0]
    aes_key = b32decode(b32_key).encode('hex')
    return aes_key
