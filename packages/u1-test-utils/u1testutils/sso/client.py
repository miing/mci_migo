# Copyright 2012, 2013 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 3, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

from ssoclient.v2 import V2ApiClient

from u1testutils.sso import environment


def get_api_client():
    base_url = environment.get_sso_base_url()
    client = V2ApiClient(base_url + '/api/v2')
    return client


def get_account_openid(email, password, token_name):
    client = get_api_client()
    response = client.login(email=email, password=password,
                            token_name=token_name)
    data = response.json()
    openid = data.get('consumer_key')
    return openid


def create_new_account(user, captcha_id=None, captcha_solution=None):
    client = get_api_client()
    data = dict(
        email=user.email,
        password=user.password,
        displayname=user.full_name
    )
    if captcha_id is not None:
        data['captcha_id'] = captcha_id
    if captcha_solution is not None:
        data['captcha_solution'] = captcha_solution
    response = client.register(data)
    return response.status_code == 201
