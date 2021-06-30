import os
import pytest

# Setting this environment variable means that the global WORK_DIR should equal TEST_WORK_DIR
# and everything should operate out of our test_data dir.
os.environ["IP_INSPECTOR_WORK_DIR_PATH"] = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data")

TEST_WORK_DIR = os.environ["IP_INSPECTOR_WORK_DIR_PATH"]
# The following should also equal their prod counterpart
TEST_ETC_DIR = os.path.join(TEST_WORK_DIR, "etc")
TEST_VAR_DIR = os.path.join(TEST_WORK_DIR, "var")
TEST_DATA_DIR = os.path.join(TEST_WORK_DIR, "data")
# explicitly set this to prevent accidental overright of a prod file
SAVED_CONFIG_PATH = os.path.join(TEST_ETC_DIR, "local.config.overrides.json")

## helpers ##
def get_real_license_key():
    from ip_inspector.config import load_configuration, DEFAULT_WORK_DIR

    saved_config_path = os.path.join(DEFAULT_WORK_DIR, "etc", "local.config.overrides.json")
    config = load_configuration(saved_config_path=saved_config_path)
    return config["maxmind"]["license_key"]


def get_inspected_ip(ip="8.8.8.8"):
    from ip_inspector import Inspector

    mmi = Inspector(maxmind_license_key=get_real_license_key())
    return mmi.get(ip)


## autouse fixtures ##
@pytest.fixture(autouse=True)
def testing_environment():
    """Safeguard to protect production data."""
    assert "IP_INSPECTOR_WORK_DIR_PATH" in os.environ


@pytest.fixture(autouse=True)
def no_local_config_overrides():
    """Start with default config, every time."""
    if os.path.exists(SAVED_CONFIG_PATH):
        os.remove(SAVED_CONFIG_PATH)


@pytest.fixture(scope="function", autouse=True)
def cleanup(request):
    """Cleanup test config items, files, and folders."""

    from ip_inspector.config import CONFIG

    # the cli main testing sets the license key for the session
    CONFIG["maxmind"]["license_key"] = None

    def _delete_local_config():
        if os.path.exists(SAVED_CONFIG_PATH):
            os.remove(SAVED_CONFIG_PATH)

    request.addfinalizer(_delete_local_config)

    def _delete_test_database():
        from ip_inspector.database import DATABASE_PATH

        if os.path.exists(DATABASE_PATH) and "test" in DATABASE_PATH:
            os.remove(DATABASE_PATH)

    request.addfinalizer(_delete_test_database)


@pytest.fixture
def refresh_data_structure():
    """Delete everything and create fresh."""
    if os.path.exists(TEST_WORK_DIR):
        import shutil

        shutil.rmtree(TEST_WORK_DIR)

    create_data_structure()


@pytest.fixture
def fresh_database():
    """Existing but empty database."""
    from ip_inspector.database import DATABASE_PATH, create_tables

    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)
    create_tables()


@pytest.fixture
def test_database(fresh_database):
    """Database with content."""
    from ip_inspector.database import (
        get_session,
        create_infrastructure_context,
        append_to_blacklist,
        append_to_whitelist,
    )

    create_infrastructure_context(get_session(), "test_default_context")
    create_infrastructure_context(get_session(), "test_another_context")

    append_to_whitelist(
        get_session(), context=1, org="float stack", asn=54, country="Canada", reference="Cartoon Network"
    )
    append_to_whitelist(get_session(), context=2, org="GOOGLE", reference="8.8.8.8")
    append_to_whitelist(get_session(), context=2, org="Microsoft", reference="Windopenw")
    append_to_whitelist(get_session(), context=700, org="GOOGLE", reference="8.8.8.8")
    append_to_whitelist(get_session(), context=2, asn=15169, reference="8.8.8.8")

    append_to_blacklist(
        get_session(), context=1, org="float stack void", asn=55, country="United States", reference="SpaceJam Network"
    )
    append_to_blacklist(get_session(), context=2, org="GOOGLE", reference="test0")
    append_to_blacklist(get_session(), context=2, org="GOOGLE", reference="test")
    append_to_blacklist(get_session(), context=2, org="G00GLE", reference=None)
    append_to_blacklist(get_session(), context=700, org="EHlo", reference="test700")
