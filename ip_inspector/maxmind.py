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

DOWNLOAD_URL = CONFIG['maxmind']['download_url']
MD5_VERIFICATION_URL = CONFIG['maxmind']['md5_verification_url']
FIELDS  = CONFIG['maxmind']['field_map_keys']


def upstream_maxmind_md5(database_name, license_key=CONFIG['maxmind']['license_key'], **requests_kwargs):
    logging.debug("Getting current MaxMind MD5 for {}.tar.gz".format(database_name))
    r = requests.get(MD5_VERIFICATION_URL.format(LICENSE_KEY=license_key, DATABASE_NAME=database_name), **requests_kwargs)
    if r.status_code != 200:
        logging.error("Got {} response code from MaxMind server".format(r.status_code))
        return False
    db_md5 = r.content.decode('utf-8')
    logging.info("Got md5={} for upstream MaxMind {}.tar.gz".format(db_md5, database_name))
    return db_md5

def get_local_md5_record(database_name):
    local_path = os.path.join(VAR_DIR, database_name+".md5")
    if os.path.exists(local_path):
        with open(os.path.join(VAR_DIR, database_name+".md5"), 'r') as fp:
            var_md5 = fp.read()
        logging.info("Got md5={} for local {}.tar.gz".format(var_md5, database_name))
        return var_md5
    return False

def update_databases(license_key=CONFIG['maxmind']['license_key'],
                     database_names=CONFIG['maxmind']['database_names'],
                     force=False,
                     **requests_kwargs):
    """Update MaxMind GeoLite2 databases
    """

    # TODO hash any local system databases and use those if they are up-to-date
    # -> have to figure out how to get the offical md5 hash of the mmdb file, rather than the tar.gz

    logging.info("Updating MaxMind databases.")
    if not license_key:
        note = ("Missing MaxMind License Key. Sign up for a free key:  https://www.maxmind.com/en/geolite2/signup"
                "\n\tThen save the key with `ip-inspector -lk value-of-key-here`")
        logging.error(note)
        raise ValueError(note)
    if not database_names:
        logging.error("No databases specified to update.")
        return False

    # Get upstream hashes once
    upstream_database_hashes = {}
    for db in database_names:
        upstream_database_hashes[db] = upstream_maxmind_md5(db, license_key, **requests_kwargs)

    # Check tar file md5 variables - update only if needed or it force is True
    if not force:
        for db in database_names.copy():
            # see if we have an existing record for this database archive
            var_md5 = get_local_md5_record(db)
            if var_md5:
                if not os.path.exists(os.path.join(DATA_DIR, db+".mmdb")):
                    logging.info("Missing DB file, ignoring local MD5 record.")
                    continue
                if var_md5 == upstream_database_hashes[db]:
                    logging.info("Local {} database appears to be up-to-date with MaxMind: {}".format(db, var_md5))
                    # remove the db from the list so it does not get updated with the same content 
                    database_names.remove(db)

    # system_default_database_files
    #system_default_database_files = CONFIG['maxmind']['system_default_database_files']
    for db in database_names:
        r = requests.get(DOWNLOAD_URL.format(LICENSE_KEY=license_key, DATABASE_NAME=db), stream=True, **requests_kwargs)
        if r.status_code == 401:
            logging.error("MaxMind Authentication failed.")
            return False
        elif r.status_code != 200:
            logging.error("Got {} from MaxMind Server.".format(r.response_code))
            return False
        target_path = os.path.join(DATA_DIR, db+'.tar.gz')
        #for _, fpath in system_default_database_files.items():
        #    if db in fpath:
        #        target_path = fpath
        #        break
        with open(target_path, 'wb') as fp:
            for chunk in r.iter_content(io.DEFAULT_BUFFER_SIZE):
                fp.write(chunk)
        if not os.path.exists(target_path):
            logging.error("Couldn't write {}".format(target_path))
            return False
        logging.debug("Wrote {}".format(target_path))
        # get md5 of file for verification
        md5_hasher = md5()
        with open(target_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hasher.update(chunk)
        file_md5 = md5_hasher.hexdigest().lower()
        logging.debug("Got md5={} for {}".format(file_md5, target_path))
        if upstream_database_hashes[db] != file_md5:
            logging.error("MD5 of content downloaded and reported content MD5 do not match. {}!={}".format(upstream_database_hashes[db], file_md5))
            return False

        # extract the DB from the tar file and delete the tar file
        tar = tarfile.open(target_path, mode="r:gz")
        for member in tar.getmembers():
            if member.name.endswith(".mmdb"):
                member.name = os.path.basename(member.name)
                tar.extract(member, path=DATA_DIR)
                if not os.path.join(DATA_DIR, member.name):
                    logging.error("Problem extracting archive.")
                    return False
                logging.info("Wrote {}".format(os.path.join(DATA_DIR, member.name)))
                with open(os.path.join(VAR_DIR, db+".md5"), 'w') as fp:
                    fp.write(upstream_database_hashes[db])
        os.remove(target_path)
        logging.info("Deleted {}".format(target_path))

    return True

def _validate_database_file_paths(database_files=CONFIG['maxmind']['local_database_files'],
                                  system_database_files=CONFIG['maxmind']['system_default_database_files']):
    """Given lists of local and system MaxMind GeoLite2 database file paths, return only existing files.
       Local databases always override system databases.
    """
    # complete the file paths if they exist
    valid_database_paths = {}
    for db in database_files:
        local_db = os.path.join(WORK_DIR, database_files[db].format(DATA_DIR=DATA_DIR))
        if os.path.exists(local_db):
            valid_database_paths[db] = local_db
        elif os.path.exists(system_database_files[db]):
            logging.debug("Local {} Database not found at '{}' -- using system db at {}".format(db, local_db, system_database_files[db]))
            valid_database_paths[db] = system_database_files[db]
        else:
            logging.warning("Couldn't find local or system '{}' database".format(db))
    return valid_database_paths

class MaxMind_IP(object):
    """A convience wrapper around the MaxMind Results for an IP address.
    """
    def __init__(self, asn_result, city_result, country_result):
        self._asn = asn_result
        self._city = city_result
        self._country = country_result
        self._raw = {} 
        self.raw['asn' ]= self._asn.raw
        self._raw['city'] = self._city.raw
        self._raw['country'] = self._country.raw
        self._ip_address = self.asn.ip_address
        self.map = self.build_map()


    def build_map(self):
        field_map = {}
        for field in FIELDS:
            if field == 'IP':
                field_map[field] = self.ip
            elif field == 'ASN':
                field_map[field] = self._asn.autonomous_system_number
            elif field == 'ORG':
                field_map[field] = self.asn.autonomous_system_organization
            elif field == 'Continent':
                field_map[field] = self.country.continent.name
            elif field == 'Country':
                field_map[field] = self.country.country.name
            elif field == 'Region':
                try:
                    field_map[field] = self.city.subdivisions[0].names['en']
                except IndexError:
                    field_map[field] = None
            elif field == 'City':
                field_map[field] = self.city.city.name
            elif field == 'Time Zone':
                field_map[field] = self.city.location.time_zone
            elif field == 'Latitude':
                field_map[field] = self.city.location.latitude
            elif field == 'Longitude':
                field_map[field] = self.city.location.longitude
            elif field == 'Accuracy Radius':
                field_map[field] = self.city.location.accuracy_radius
            else:
                logging.error("Field not mapped to data: {}".format(field))
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
        if field in self.map:
            return self.map[field]
        logging.error("{} is not mapped to a data value.".format(field))
        return None

    def __str__(self):
        txt = "\t--------------------\n"
        for field in FIELDS:
            if self.get(field):
                txt += "\t{}: {}\n".format(field, self.get(field))
            else:
                txt += "\t{}: {}\n".format(field, '')
        return(txt)

class Client():

    def __init__(self,
                 database_files=CONFIG['maxmind']['local_database_files'],
                 system_database_files=CONFIG['maxmind']['system_default_database_files'],
                 license_key=CONFIG['maxmind']['license_key'],
                 **requests_kwargs):
        # complete the file paths if they exist
        self.database_files = _validate_database_file_paths(database_files=database_files,
                                                            system_database_files=system_database_files)
        if not self.database_files:
            logging.warning("No MaxMind GeoLite2 Databases. Attempting to download.")
            if not update_databases(license_key=license_key, **requests_kwargs):
                sys.exit(1)
            else:
                self.database_files = _validate_database_file_paths(database_files=database_files,
                                                            system_database_files=system_database_files)

        self.asn_reader = self.city_reader = self.country_reader = None
        if self.database_files['asn']:
            self.asn_reader = geoip2.database.Reader(self.database_files['asn'])
        if self.database_files['city']:
            self.city_reader = geoip2.database.Reader(self.database_files['city'])
        if self.database_files['country']:
            self.country_reader = geoip2.database.Reader(self.database_files['country'])

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

    def _scrub(self, data, lang='en'):
        """Scrub the raw results to remove any language data we don't care about.
        """
        return None

    def get(self, ip):
        try:
            return MaxMind_IP(self.asn(ip), self.city(ip), self.country(ip))
        except AddressNotFoundError as e:
            logging.warning(e)
            return None
