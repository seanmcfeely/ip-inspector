
import os
import sys
import json
import yaml
import logging
import collections.abc

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

HOME_PATH = os.path.dirname(os.path.realpath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(HOME_PATH, 'etc', 'default.config.yaml')
WORK_DIR = os.path.join(os.path.join(os.path.expanduser("~")), '.ip_inspector')
ETC_DIR = os.path.join(WORK_DIR, 'etc')
VAR_DIR = os.path.join(WORK_DIR, 'var')
DATA_DIR = os.path.join(WORK_DIR, 'data')

# Make sure the directories we need actually exist
for path in [WORK_DIR, DATA_DIR, VAR_DIR, ETC_DIR]:
    if not os.path.isdir(path):
        try:
            os.mkdir(path)
        except Exception as e:
            sys.stderr.write("ERROR: cannot create directory {0}: {1}\n".format(path, e))
            sys.exit(1)

# any overrides the user provides, such as maxmind license key are saved here
SAVED_CONFIG_PATH = os.path.join(WORK_DIR, ETC_DIR, 'local.config.overrides.json')

def update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = update(d.get(k, {}), v)
        else:
            d[k] = v
    return d

def _load_saved(saved_config_path=SAVED_CONFIG_PATH):
    saved = {}
    if os.path.exists(saved_config_path):
        try:
            with open(saved_config_path, 'r') as fp:
                saved = json.load(fp)
        except Exception as e:
            logging.warning("Problem loading saved configuration file: {}".format(e))
    return saved

def _load_this_(config_path):
    config = None
    try:
        with open(config_path) as c:
           config = yaml.load(c, Loader=Loader)
    except:
        logging.exception("Problem loading config: {}".format(config_path))
        return False
    return config

def load(config_path=None, saved_config_path=SAVED_CONFIG_PATH):
    """Load configuration files. The default YAML config is always loaded first. Next, any saved overrides or non-default
       configuration items are loaded from any local json file at saved_config_path. Finally, any valid config_path passed will be loaded last.
       Later configs will override values found in earlier configs.

    :param config_paths (str): Path to a yaml configuration file to override defaults.
    :param saved_config_path (str): Path to a saved json configuration at a location different than the default.
    """

    # load the default config
    config = _load_this_(DEFAULT_CONFIG_PATH)

    # load any saved overrides and update
    config = update(config, _load_saved(saved_config_path))

    # check to see if a different saved_config_path has been defined
    if 'saved_config_path' in config['default'] and config['default']['saved_config_path'] != SAVED_CONFIG_PATH:
        if os.path.exists(config['default']['saved_config_path']):
            logging.debug("loading saved config at {}".format(config['default']['saved_config_path']))
            config = update(config, _load_saved(config['default']['saved_config_path']))
        else:
            logging.debug("{} DOES NOT EXIST".format(config['default']['saved_config_path']))
            save({'default': { 'saved_config_path': SAVED_CONFIG_PATH}})

    # load any passed yaml config
    if config_path:
        config = _load_this_(config_path)
        return config

    return config


def save(item, config_path=SAVED_CONFIG_PATH):
    """Save configuration overrides to a local json config file.

    :param update (dict): A dictionary containing the key values to be updated.
    :param config_path (str): The path to save the json config to.
    """

    saved = _load_saved(config_path)
    new_saved = update(saved, item)
    try:
        logging.debug("Saving {} to {}".format(item, config_path))
        with open(config_path, 'w') as config:
            config.write(json.dumps(new_saved, indent=2, sort_keys=True))
        return True
    except:
        logging.exception("Problem saving config overrides: {}".format(config_path))
        return False


# Save the working dir if we don't have it
if not os.path.exists(SAVED_CONFIG_PATH):
    save({
            'default': {
                'work_dir': WORK_DIR
            }
        })

CONFIG = load()

# handle an override
if CONFIG['default']['work_dir'] and os.path.exists(CONFIG['default']['work_dir']):
    WORK_DIR = CONFIG['default']['work_dir']