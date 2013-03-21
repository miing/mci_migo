import os


APPLICATIONS = '/+applications'
CONSUMER = '/consumer'
DEVICES = '/device-list'
EDIT = '/+edit'
EMAILS = '/+emails'
ENTER_TOKEN = '/+enter_token'
FORGOT_PASSWORD = '/+forgot_password'
HOME = '/'
LOGIN = '/+login'
LOGOUT = '/+logout'
NEW_ACCOUNT = '/+new_account'
NEW_EMAIL = '/+new-email'
REMOVE_EMAIL = '/+remove-email'
VERIFY_EMAIL = '/+verify-email'

API_REGISTER = '/accounts'


def get_base_url(default='http://localhost:8000'):
    base_url = os.environ.get('SST_BASE_URL', default).rstrip('/')
    return base_url
