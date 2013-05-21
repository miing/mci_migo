# 3) Check the following links on the login page to ensure they are all
# working:
# Login support, Find out more, Source code for this service, AGPL, Terms of
# Service, Privacy Policy, ubuntu logo {ubuntu.com}

# This tests only the links with link text, not the Ubuntu logo.
from sst.actions import (
    assert_title,
    assert_element,
    go_to,
    wait_for,
)
from u1testutils.sst import config

from acceptance import urls

from identityprovider.utils import get_current_brand


config.set_base_url_from_env()

go_to(urls.HOME)
wait_for(assert_title, 'Log in')

if get_current_brand() == 'ubuntuone':
    links = (
        ('Terms of use', 'https://one.ubuntu.com/terms/'),
        ('Privacy', 'https://one.ubuntu.com/privacy/'),
        ('Login support', 'https://forms.canonical.com/sso-support/'),
        ('Choose your language', urls.get_base_url() + '/set_language'),
    )
else:
    links = (
        ('Login support', 'https://forms.canonical.com/sso-support/'),
        ('Find out more', urls.get_base_url() + '/+description'),
        ('Source code for this service',
         'https://launchpad.net/canonical-identity-provider'),
        ('AGPL', 'http://www.gnu.org/licenses/agpl-3.0.html'),
        ('Terms of Service', 'http://ubuntu.com/legal'),
        ('Privacy Policy', 'http://ubuntu.com/legal#privacy'),
    )

for link_text, href in links:
    elems = assert_element(tag='a', text=link_text)
    assert len(elems) == 1, 'Must have a single link for ' + link_text
    real_href = elems[0].get_attribute('href')

    assert real_href == href, ('Link for %s should be %s (got %s instead)' %
                               (link_text, href, real_href))
