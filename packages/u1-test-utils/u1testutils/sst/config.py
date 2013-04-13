import os
from sst.actions import set_base_url


DEFAULT_BASE_URL = 'http://localhost:8000'


def set_base_url_from_env(default_url=DEFAULT_BASE_URL):
    """Set the base URL for SST tests from the env or default."""
    set_base_url(get_base_url_from_env(default_url))


def get_base_url_from_env(default_url=DEFAULT_BASE_URL):
    base_url = os.environ.get('SST_BASE_URL', default_url)
    return base_url.rstrip('/')
