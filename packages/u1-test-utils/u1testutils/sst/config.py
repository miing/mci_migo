import os
from sst.actions import set_base_url


def set_base_url_from_env(default_to='http://localhost:8000/'):
    """Set the base URL for SST tests from the env or default."""
    base_url = os.environ.get('SST_BASE_URL', default_to)
    set_base_url(base_url)
