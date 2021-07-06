import os
import sys
import pytest

from tests import *


def test_environment_variable_work_override():
    from ip_inspector.config import WORK_DIR, ETC_DIR, VAR_DIR, DATA_DIR

    assert "IP_INSPECTOR_WORK_DIR_PATH" in os.environ
    # these should all agree because of the IP_INSPECTOR_WORK_DIR_PATH environment variable set in tests/__init__.py
    assert TEST_WORK_DIR == WORK_DIR
    assert ETC_DIR == TEST_ETC_DIR
    assert VAR_DIR == TEST_VAR_DIR
    assert DATA_DIR == TEST_DATA_DIR


def test_configuration_defaults():
    from ip_inspector.config import _load_yaml_defaults

    # should just load the defaults
    config = _load_yaml_defaults()
    assert isinstance(config, dict)
    # account number and license should be empty by default
    assert not config["maxmind"]["account_number"]
    assert not config["maxmind"]["license_key"]
    assert config["default"]["work_dir"] == "OVERRIDE"


def test_save_configuration_overrides():
    from ip_inspector.config import load_configuration, save_configuration, _load_saved_json

    assert not os.path.exists(SAVED_CONFIG_PATH)
    overrides = {}
    overrides["default"] = {"work_dir": TEST_WORK_DIR}
    save_configuration(overrides, config_path=SAVED_CONFIG_PATH)

    assert os.path.exists(SAVED_CONFIG_PATH)
    saved_overrides = _load_saved_json(SAVED_CONFIG_PATH)
    assert saved_overrides["default"]["work_dir"] == TEST_WORK_DIR
    # there should only be the one override we've saved
    assert len(saved_overrides.keys()) == 1

    # now reload the config with the saved overrides
    config = load_configuration(saved_config_path=SAVED_CONFIG_PATH)
    assert config["default"]["work_dir"] == TEST_WORK_DIR

    # save a copy of the entire config
    save_configuration(config, config_path=SAVED_CONFIG_PATH)
    # assert the config equals what is loaded from saved
    assert config == _load_saved_json(SAVED_CONFIG_PATH)
    assert os.remove(SAVED_CONFIG_PATH) is None


def test_load_configuration():
    from ip_inspector.config import load_configuration, save_configuration, CONFIG, WORK_DIR

    config = load_configuration()
    assert not config["maxmind"]["license_key"]
    assert not CONFIG["maxmind"]["license_key"]
    # environment variable for work_dir continues to override everything
    assert config["default"]["work_dir"] == TEST_WORK_DIR
    # save the work dir
    overrides = {"default": {"work_dir": "this/is/bogus"}}
    # environment variable for work_dir continues to override everything
    save_configuration(overrides, config_path=SAVED_CONFIG_PATH)
    config = load_configuration(saved_config_path=SAVED_CONFIG_PATH)
    assert config["default"]["work_dir"] == WORK_DIR == TEST_WORK_DIR
    assert CONFIG == config

    config = load_configuration(saved_config_path=SAVED_CONFIG_PATH)
    assert "tracking_context" not in config["default"]
    overrides = {"default": {"tracking_context": "ztestingz"}}
    save_configuration(overrides, config_path=SAVED_CONFIG_PATH)
    config = load_configuration(saved_config_path=SAVED_CONFIG_PATH)
    assert config["default"]["tracking_context"] == "ztestingz"

