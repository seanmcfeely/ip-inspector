
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

# any overrides the user provides, such as maxmind license key are saved here
SAVED_CONFIG_PATH = os.path.join(HOME_PATH, 'etc', 'local.config.overrides.json')


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

def load(config_path=None, saved_config_path=SAVED_CONFIG_PATH):
    """Load configuration files. The default YAML config is always loaded first. Next, any saved overrides or non-default
       configuration items are loaded from any local json file at saved_config_path. Finally, any valid config_path passed will be loaded last.
       Later configs will override values found in earlier configs.

    :param config_paths (str): Path to a yaml configuration file to override defaults.
    :param saved_config_path (str): Path to a saved json configuration at a location different than the default.
    """
    def _load_this_(config_path):
        config = None
        try:
            with open(config_path) as c:
               config = yaml.load(c, Loader=Loader)
        except:
            logging.exception("Problem loading config: {}".format(config_path))
            return False
        return config

    # load the default config
    config = _load_this_(DEFAULT_CONFIG_PATH)

    # load any saved overrides and update
    config = update(config, _load_saved(saved_config_path))

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
        with open(config_path, 'w') as config:
            config.write(json.dumps(new_saved, indent=2, sort_keys=True))
    except:
        logging.exception("Problem saving config overrides: {}".format(config_path))
        return False

CONFIG = load()
