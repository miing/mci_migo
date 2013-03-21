import os.path

from django_configglue.utils import configglue

from identityprovider.schema import schema


# get location of local cfg files
local_configs = os.environ.get('CONFIGGLUE_LOCAL_CONFIG',
    '../../../local_config/local.cfg:local.cfg').split(':')

# get absolute path for config files
current_dir = os.path.dirname(os.path.abspath(__file__))
config_files = map(lambda x: os.path.join(current_dir, x),
                   ['config/main.cfg'] + local_configs)

# glue everything together
configglue(schema, config_files, __name__)
