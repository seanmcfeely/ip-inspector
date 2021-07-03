"""Everything MaxMind functionality."""

import io
import os
import sys
import shutil
import tarfile
import logging
import requests

import geoip2.database
from geoip2.errors import *

from hashlib import md5
from ip_inspector.config import CONFIG, WORK_DIR, DATA_DIR, VAR_DIR

LOGGER = logging.getLogger("ip-inspector.maxmind")

# CONFIG = load_configuration()
DOWNLOAD_URL = CONFIG["maxmind"]["download_url"]
FIELDS = CONFIG["maxmind"]["field_map_keys"]


def upstream_maxmind_md5(
    database_name: str, license_key: str = CONFIG["maxmind"]["license_key"], **requests_kwargs
) -> str:
    """Get the MD5 of the most recent MaxMind database.

    Args:
        database_name: the name of the database to look up
        license_key: MaxMind license key with adequate permissions.

    Returns:
        The MD5 hash of the most recent database MaxMind has to offer,
        as a string.
    """
    md5_verification_url = CONFIG["maxmind"]["md5_verification_url"]
    LOGGER.debug(f"Getting current MaxMind MD5 for {database_name}.tar.gz")
    r = requests.get(
        md5_verification_url.format(LICENSE_KEY=license_key, DATABASE_NAME=database_name), **requests_kwargs
    )
    if r.status_code != 200:
        LOGGER.error(f"Got {r.status_code} response code from MaxMind server")
        return False
    db_md5 = r.content.decode("utf-8")
    LOGGER.info(f"Got md5={db_md5} for upstream MaxMind {database_name}.tar.gz")
    return db_md5


def get_local_md5_record(database_name):
    """Get the MD5 of the current MaxMind database.

    This is the database that's being used locally.

    Args:
        database_name: the name of the database to hash.

    Returns:
        The MD5 hash of the local MaxMind database currently being used.
    """
    local_path = os.path.join(VAR_DIR, database_name + ".md5")
    if os.path.exists(local_path):
        with open(os.path.join(VAR_DIR, database_name + ".md5"), "r") as fp:
            var_md5 = fp.read()
        LOGGER.info("Got md5={var_md5} for local {database_name}.tar.gz")
        return var_md5
    return False


def update_databases(
    license_key=CONFIG["maxmind"]["license_key"],
    database_names=CONFIG["maxmind"]["database_names"],
    force=False,
    **requests_kwargs,
):
    """Update MaxMind GeoLite2 databases.

    Download the most recent GeoLite2 databases for local use.

    Args:
        license_key: MaxMind license key with adequate permissions.
        database_names: list of MaxMind database names to collect.
        force: If true, update even if we already have a local copy.

    Returns:
        True on success.
    """

    LOGGER.info("Updating MaxMind databases.")
    if not license_key:
        note = (
            "Missing MaxMind License Key. Sign up for a free key:  https://www.maxmind.com/en/geolite2/signup"
            "\n\tThen save the key with `ip-inspector -lk value-of-key-here`"
        )
        LOGGER.critical(note)
        return False
    if not database_names:
        LOGGER.error("No databases specified to update.")
        return False

    # Get upstream hashes once
    upstream_database_hashes = {}
    for db in database_names:
        upstream_database_hashes[db] = upstream_maxmind_md5(db, license_key, **requests_kwargs)

    needed_databased = database_names.copy()

    # Check tar file md5 variables - update only if needed or it force is True
    if not force:
        for db in database_names:
            # see if we have an existing record for this database archive
            var_md5 = get_local_md5_record(db)
            if var_md5:
                if not os.path.exists(os.path.join(DATA_DIR, db + ".mmdb")):
                    LOGGER.info("Missing DB file, ignoring local MD5 record.")
                    continue
                if var_md5 == upstream_database_hashes[db]:
                    LOGGER.info(f"Local {db} database appears to be up-to-date with MaxMind: {var_md5}")
                    # remove the db from the list so it does not get updated with the same content
                    needed_databased.remove(db)

    for db in needed_databased:
        r = requests.get(DOWNLOAD_URL.format(LICENSE_KEY=license_key, DATABASE_NAME=db), stream=True, **requests_kwargs)
        if r.status_code == 401:
            LOGGER.error("MaxMind Authentication failed.")
            return False
        elif r.status_code != 200:
            LOGGER.error("Got {r.response_code} from MaxMind Server.")
            return False

        target_path = os.path.join(DATA_DIR, db + ".tar.gz")
        with open(target_path, "wb") as fp:
            for chunk in r.iter_content(io.DEFAULT_BUFFER_SIZE):
                fp.write(chunk)
        if not os.path.exists(target_path):
            LOGGER.error("Couldn't write {}".format(target_path))
            return False
        LOGGER.debug("Wrote {}".format(target_path))

        # get md5 of file for verification
        md5_hasher = md5()
        with open(target_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hasher.update(chunk)
        file_md5 = md5_hasher.hexdigest().lower()
        LOGGER.debug(f"Got md5={file_md5} for {target_path}")
        if upstream_database_hashes[db] != file_md5:
            LOGGER.error(
                f"MD5 of content downloaded and reported content MD5 do not match. {upstream_database_hashes[db]}!={file_md5}"
            )
            return False

        # extract the DB from the tar file and delete the tar file
        tar = tarfile.open(target_path, mode="r:gz")
        for member in tar.getmembers():
            if member.name.endswith(".mmdb"):
                member.name = os.path.basename(member.name)
                tar.extract(member, path=DATA_DIR)
                if not os.path.join(DATA_DIR, member.name):
                    LOGGER.error("Problem extracting archive.")
                    return False
                LOGGER.info(f"Wrote {os.path.join(DATA_DIR, member.name)}")
                with open(os.path.join(VAR_DIR, db + ".md5"), "w") as fp:
                    fp.write(upstream_database_hashes[db])
        os.remove(target_path)
        LOGGER.info(f"Deleted {target_path}")

    return True


def _validate_database_file_paths(
    database_files=CONFIG["maxmind"]["local_database_files"],
    system_database_files=CONFIG["maxmind"]["system_default_database_files"],
):
    """Given lists of local and system MaxMind GeoLite2 database file paths, return only existing files.
    Local databases always override system databases.
    """
    valid_database_paths = {}
    for db in database_files:
        local_db = os.path.join(WORK_DIR, database_files[db].format(DATA_DIR=DATA_DIR))
        if os.path.exists(local_db):
            valid_database_paths[db] = local_db
        elif os.path.exists(system_database_files[db]):
            LOGGER.debug(
                f"Local {db} Database not found at '{local_db}' -- using system db at {system_database_files[db]}"
            )
            valid_database_paths[db] = system_database_files[db]
        else:
            LOGGER.warning(f"Couldn't find local or system '{db}' database")
    return valid_database_paths


class MaxMind_IP(object):
    """A convienice wrapper around the MaxMind Results for an IP address."""

    def __init__(self, asn_result, city_result, country_result):
        self._asn = asn_result
        self._city = city_result
        self._country = country_result
        self._raw = {}
        self.raw["asn"] = self._asn.raw
        self._raw["city"] = self._city.raw
        self._raw["country"] = self._country.raw
        self._ip_address = self.asn.ip_address
        self.map = self.build_map()

    def build_map(self):
        field_map = {}
        for field in FIELDS:
            if field == "IP":
                field_map[field] = self.ip
            elif field == "ASN":
                field_map[field] = self._asn.autonomous_system_number
            elif field == "ORG":
                field_map[field] = self.asn.autonomous_system_organization
            elif field == "Continent":
                field_map[field] = self.country.continent.name
            elif field == "Country":
                field_map[field] = self.country.country.name
            elif field == "Region":
                try:
                    field_map[field] = self.city.subdivisions[0].names["en"]
                except IndexError:
                    field_map[field] = None
            elif field == "City":
                field_map[field] = self.city.city.name
            elif field == "Time Zone":
                field_map[field] = self.city.location.time_zone
            elif field == "Latitude":
                field_map[field] = self.city.location.latitude
            elif field == "Longitude":
                field_map[field] = self.city.location.longitude
            elif field == "Accuracy Radius":
                field_map[field] = self.city.location.accuracy_radius
            else:
                LOGGER.error("Field not mapped to data: {}".format(field))
                field_map[field] = None
        return field_map

    @property
    def asn(self):
        return self._asn

    @property
    def city(self):
        return self._city

    @property
    def country(self):
        return self._country

    @property
    def ip(self):
        return self._ip_address

    @property
    def raw(self):
        return self._raw

    def get(self, field):
        return self.map.get(field, None)

    def __str__(self):
        txt = "\t--------------------\n"
        for field in FIELDS:
            if self.get(field):
                txt += f"\t{field}: {self.get(field)}\n"
            else:
                txt += f"\t{field}: \n"
        return txt


class Client:
    def __init__(
        self,
        database_files=CONFIG["maxmind"]["local_database_files"],
        system_database_files=CONFIG["maxmind"]["system_default_database_files"],
        license_key=CONFIG["maxmind"]["license_key"],
        **requests_kwargs,
    ):
        # complete the file paths if they exist
        self.database_files = _validate_database_file_paths(
            database_files=database_files, system_database_files=system_database_files
        )

        self.asn_reader = self.city_reader = self.country_reader = None
        if self.database_files:
            if self.database_files["asn"]:
                self.asn_reader = geoip2.database.Reader(self.database_files["asn"])
            if self.database_files["city"]:
                self.city_reader = geoip2.database.Reader(self.database_files["city"])
            if self.database_files["country"]:
                self.country_reader = geoip2.database.Reader(self.database_files["country"])

    @property
    def asn(self):
        """The ASN DB Reader."""
        return self.asn_reader.asn

    @property
    def city(self):
        """The City DB Reader."""
        return self.city_reader.city

    @property
    def country(self):
        """The Country DB Reader."""
        return self.country_reader.country

    def _scrub(self, data, lang="en"):
        """Scrub the raw results to remove any language data we don't care about."""
        # NotImplemented
        return None

    def get(self, ip):
        try:
            return MaxMind_IP(self.asn(ip), self.city(ip), self.country(ip))
        except AddressNotFoundError as e:
            LOGGER.warning(e)
            return None
