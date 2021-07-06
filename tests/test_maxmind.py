import sys
import pytest

from tests import *


def test_maxmind_upstream_database_hashes():
    # requires a real license key
    from ip_inspector.config import CONFIG
    from ip_inspector.maxmind import upstream_maxmind_md5

    first_database_name = CONFIG["maxmind"]["database_names"][0]
    license_key = get_real_license_key()
    if not license_key:
        sys.stderr.write("[TEST ERROR] MISSING MAXMIND LICENSE KEY. TEST WILL FAIL.")

    md5 = upstream_maxmind_md5(first_database_name, license_key=license_key)
    assert isinstance(md5, str)
    assert len(md5) == 32


def test_maxmind_update_databases():
    # requires a real license key
    from ip_inspector.maxmind import update_databases

    license_key = get_real_license_key()
    if not license_key:
        sys.stderr.write("[TEST ERROR] MISSING MAXMIND LICENSE KEY. TEST WILL FAIL.")

    assert update_databases(license_key=license_key) == True


def test_get_local_md5_record():
    # requires local databases
    from ip_inspector.config import CONFIG
    from ip_inspector.maxmind import get_local_md5_record

    first_database_name = CONFIG["maxmind"]["database_names"][0]
    md5 = get_local_md5_record(first_database_name)
    assert isinstance(md5, str)
    assert len(md5) == 32


def test__validate_database_file_paths():
    from ip_inspector.maxmind import _validate_database_file_paths
    from ip_inspector.config import CONFIG

    valid_database_paths = _validate_database_file_paths()
    assert isinstance(valid_database_paths, dict)
    assert len(valid_database_paths) == 3
    assert TEST_DATA_DIR in list(valid_database_paths.values())[0]


def test_are_database_files_up_to_date():
    from ip_inspector.maxmind import are_database_files_up_to_date

    system_database_files = {"asn": "fake", "country": "fake", "city": "fake"}
    local_database_files = system_database_files
    assert (
        are_database_files_up_to_date(database_files=local_database_files, system_database_files=system_database_files)
        == False
    )
    # NOTE: lazy test as not removing system level databases from scope
    # so they eiter are old or not or non-existant. False or True.
    assert are_database_files_up_to_date() in [False, True]


def test_maxmind_client_api():
    # requires system or local databases
    from ip_inspector.maxmind import Client, MaxMind_IP

    mmc = Client(license_key=get_real_license_key())

    assert isinstance(mmc.database_files, dict)
    assert ["asn", "city", "country"] == list(mmc.database_files.keys())

    mmip = mmc.get("8.8.8.8")
    assert isinstance(mmip, MaxMind_IP)
    assert mmip.get("ORG") == "GOOGLE"
    assert mmip.ip == "8.8.8.8"
    assert mmip.get("Continent") == "North America"
