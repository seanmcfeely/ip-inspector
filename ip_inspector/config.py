"""Configuration functionality."""

import os
import sys
import json
import yaml
import logging
import collections.abc

from typing import Dict, Mapping, List

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader  # type: ignore

LOGGER = logging.getLogger("ip-inspector.config")

HOME_PATH = os.path.dirname(os.path.realpath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(HOME_PATH, "etc", "default.config.yaml")

# helps with tests to keep the default recorded
DEFAULT_WORK_DIR = os.path.join(os.path.join(os.path.expanduser("~")), ".ip_inspector")
if "IP_INSPECTOR_WORK_DIR_PATH" in os.environ:
    # has to be set before the lib is loaded
    WORK_DIR = os.environ["IP_INSPECTOR_WORK_DIR_PATH"]
else:
    WORK_DIR = DEFAULT_WORK_DIR

ETC_DIR = os.path.join(WORK_DIR, "etc")
VAR_DIR = os.path.join(WORK_DIR, "var")
DATA_DIR = os.path.join(WORK_DIR, "data")


CONFIG_SEARCH_PATHS = [
    DEFAULT_CONFIG_PATH,
]

ignore_system_config = os.environ.get("IP_INSPECTOR_IGNORE_SYSTEM_CONFIG")
if ignore_system_config and ignore_system_config.lower() == "true":
    ignore_system_config = True  # type: ignore

if not ignore_system_config:
    CONFIG_SEARCH_PATHS.append("/etc/ip_inspector/ip-inspector.yaml")
    CONFIG_SEARCH_PATHS.append("/opt/ace/etc/ip-inspector.yaml")

# Any overrides the user provides, such as the maxmind license key are saved here.
SAVED_CONFIG_PATH = os.path.join(WORK_DIR, ETC_DIR, "local.config.overrides.json")
# System level overrides can be supplied here:
SYSTEM_CONFIG_PATH = os.path.join(os.sep, "etc", "ip_inspector", "system.config.overrides.json")


def _create_data_structure():
    """Create the required directory structure."""
    for path in [WORK_DIR, DATA_DIR, VAR_DIR, ETC_DIR]:
        if not os.path.isdir(path):
            try:
                os.mkdir(path)
            except Exception as e:
                sys.stderr.write(f"ERROR: cannot create directory {path}: {e}\n")
                sys.exit(1)


def _update_config_dictionary(existing_config: Dict, new_items: Mapping) -> Dict:
    """Update the existing config the new config items.

    Args:
        existing_config: An existing config dictionary
        new_items: Items to override or introduce into the existing_config.

    Returns:
        An updated config dictionary.
    """
    for k, v in new_items.items():
        if isinstance(v, collections.abc.Mapping):
            existing_config[k] = _update_config_dictionary(existing_config.get(k, {}), v)
        else:
            existing_config[k] = v
    return existing_config


def _load_saved_json(saved_config_path: str = SAVED_CONFIG_PATH) -> Dict:
    """Load a JSON config.

     Args:
        saved_config_path: Path to a saved json configuration.

    Returns:
        The config as a dictionary.
    """
    saved = {}
    if os.path.exists(saved_config_path):
        try:
            with open(saved_config_path, "r") as fp:
                saved = json.load(fp)
        except Exception as e:
            LOGGER.warning("Problem loading saved configuration file: {}".format(e))
    return saved


def _load_yaml_configs(config_paths: List[str] = CONFIG_SEARCH_PATHS) -> Dict:
    """Load a YAML configs.

    The default config is in YAML format. It's loaded first, and then any other
    in the config search path.

    Args:
        config_paths: paths to YAML configs that should be loaded.

    Returns:
        A the config as a dictionary.
    """
    config: Dict = {}
    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path) as c:
                    updated_config = _update_config_dictionary(config, yaml.load(c, Loader=Loader))
            except:
                LOGGER.exception("Problem loading config: {}".format(config_path))
                return config
            else:
                config = updated_config
    return config


def load_configuration(
    config_paths: List[str] = CONFIG_SEARCH_PATHS, saved_config_path: str = SAVED_CONFIG_PATH
) -> Dict:
    """Load configuration from config files.

    The default YAML `config_path` (default of `DEFAULT_CONFIG_PATH`) is always loaded first.
    Next, any saved overrides or non-default configuration items are loaded from the
    local json file at `saved_config_path`. Finally, any valid `config_path`, passed to this function,
    will be loaded. Later configs override values found in earlier configs.

    Args:
        config_paths: Path to a yaml configuration file to override defaults.
        saved_config_path: Path to a saved json configuration.

    Returns:
        The configuration as a dictionary.
    """

    # load the default config and any overrides.
    config = _load_yaml_configs(config_paths)

    # load additional config paths

    # load any saved system overrides and update the config, unless an environment variable tells us otherwise
    ignore_system_config = os.environ.get("IP_INSPECTOR_IGNORE_SYSTEM_CONFIG")
    if ignore_system_config and ignore_system_config.lower() == "true":
        ignore_system_config = True  # type: ignore
    if not ignore_system_config and os.path.exists(SYSTEM_CONFIG_PATH):
        config = _update_config_dictionary(config, _load_saved_json(SYSTEM_CONFIG_PATH))

    # load any saved user-level overrides and update the config
    config = _update_config_dictionary(config, _load_saved_json(saved_config_path))

    # work dir environment variable overrides everything for work_dir
    if "IP_INSPECTOR_WORK_DIR_PATH" in os.environ:
        config["default"]["work_dir"] = os.environ["IP_INSPECTOR_WORK_DIR_PATH"]

    return config


def save_configuration(overrides: Dict, config_path: str = SAVED_CONFIG_PATH) -> bool:
    """Save configuration overrides to a local json config file.

    This allows for configuration changes to persist.

    Args:
        overrides: A dictionary containing the key values to be saved to `config_path`.
        config_path: The path to save the json config to.

    Returns:
        True on success.
    """
    # load any existing overrides that are already saved and update with the new overrides.
    saved = _load_saved_json(config_path)
    new_saved = _update_config_dictionary(saved, overrides)
    try:
        LOGGER.debug(f"Saving {overrides} to {config_path}")
        with open(config_path, "w") as config:
            config.write(json.dumps(new_saved, indent=2, sort_keys=True))
        return True
    except:
        LOGGER.exception("Problem saving config overrides: {}".format(config_path))
        return False


def update_configuration(config_override_path: str, saved_config_path: str = SAVED_CONFIG_PATH) -> bool:
    """Update the `saved_config_path` with the contents of the override config."""
    overrides = _load_saved_json(config_override_path)
    return save_configuration(overrides, config_path=saved_config_path)


# Load the CONFIG and update GLOBALS accordingly
CONFIG = load_configuration()
if CONFIG["default"]["work_dir"] == "OVERRIDE":
    # this means there were no overrides
    CONFIG["default"]["work_dir"] = WORK_DIR
elif WORK_DIR != CONFIG["default"]["work_dir"]:
    # a local or system level config overrode the defaults, update everything
    WORK_DIR = CONFIG["default"]["work_dir"]
    ETC_DIR = os.path.join(WORK_DIR, "etc")
    VAR_DIR = os.path.join(WORK_DIR, "var")
    DATA_DIR = os.path.join(WORK_DIR, "data")
    SAVED_CONFIG_PATH = os.path.join(WORK_DIR, ETC_DIR, "local.config.overrides.json")

# Will raise exception if permissions are inadequate.
_create_data_structure()
