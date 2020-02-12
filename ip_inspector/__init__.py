import os
import shutil
import logging

from ip_inspector.config import CONFIG, WORK_DIR
from ip_inspector import maxmind, tor


class Inspected_IP(maxmind.MaxMind_IP):
    """A MaxMind_IP result with whitelist/blacklist metadata added."""

    def __init__(self, asn_result, city_result, country_result, blacklist_type=None, whitelist_type=None, tor_exit_node=False):
        super().__init__(asn_result, city_result, country_result)
        self._blacklist_str = '{} (!BLACKLISTED!)'
        self._whitelist_str = '{} (whitelisted)'
        self.blacklist_reason = blacklist_type
        self.whitelist_reason = whitelist_type
        self._blacklisted = False
        self._whitelisted = False
        if blacklist_type and whitelist_type:
            logging.error("IP is both whitelisted and blacklisted!")
        if blacklist_type:
            self._blacklisted = True
        if whitelist_type:
            self._whitelisted = True
        self.is_tor = tor_exit_node
        # expand the map
        if self.is_tor:
            self.map['TOR'] = self.is_tor

    def set_blacklist(self, blacklist_type):
        self.blacklist_reason = blacklist_type
        self._blacklisted = True

    def set_whitelist(self, whitelist_type):
        self.whitelist_reason = whitelist_type
        self._whitelisted = True

    @property
    def is_whitelisted(self):
        return self._whitelisted

    @property
    def is_blacklisted(self):
        return self._blacklisted

    @property
    def reason(self):
        if self.is_blacklisted:
            return self.map[self.blacklist_reason]
        if self.is_whitelisted:
            return self.map[self.whitelist_reason]

    def __str__(self):
        if self.is_blacklisted:
            self.map[self.blacklist_reason] = self._blacklist_str.format(self.get(self.blacklist_reason))
        if self.is_whitelisted:
            self.map[self.whitelist_reason] = self._whitelist_str.format(self.get(self.whitelist_reason))
        txt = "\t--------------------\n"
        for field in self.map:
            if field == 'IP' and self.is_tor:
                txt += "\t{}: {}\n".format(field, "{} (TOR EXIT)".format(self.get(field)))
            elif self.get(field):
                txt += "\t{}: {}\n".format(field, self.get(field))
            else:
                txt += "\t{}: {}\n".format(field, '')
        return(txt)


class Inspector():
    """An a computer network inspector for the primary purpose of
       Intel & Detection. Wrapper around maxmind.Client.

    :intel_agents: API objects to query for resources.
    :blacklists: Detection files.
    :whitelists: good guys.
    """

    def __init__(self,
                 mmc: maxmind.Client = maxmind.Client(),
                 blacklists=CONFIG['default']['blacklists'],
                 whitelists=CONFIG['default']['whitelists'],
                 tor_exits: tor.ExitNodes = tor.ExitNodes()
                 ):
       
        self.mmc = mmc
        self.blacklists = {}
        self.whitelists = {}
        self.tor_exits = tor_exits
        for bl_type, bl_path in blacklists.items():
            full_path = bl_path
            if not os.path.exists(full_path):
                full_path = os.path.join(WORK_DIR, full_path)
                if not os.path.exists(full_path):
                    logging.debug("No {} blacklist found at {} or {}".format(bl_type, bl_path, full_path))
                    continue
            with open(full_path, 'r') as fp:
                self.blacklists[bl_type] = [line.strip() for line in fp.readlines()]
        for wl_type, wl_path in whitelists.items():
            full_path = wl_path
            if not os.path.exists(full_path):
                full_path = os.path.join(WORK_DIR, full_path)
                if not os.path.exists(full_path):
                    logging.debug("No {} whitelist found at {} or {}".format(wl_type, wl_path, full_path))
                    continue
            with open(full_path, 'r') as fp:
                self.whitelists[wl_type] = [line.strip() for line in fp.readlines()]


    def inspect(self, ip):
        """Check IP metadata against blacklist detections.

        :param ip: IPv4 or IPv6
        :return: 
        """
        try:
            IIP = Inspected_IP(self.mmc.asn(ip), self.mmc.city(ip), self.mmc.country(ip), tor_exit_node=self.tor_exits.is_exit_node(ip))
            for blacklist_type in self.blacklists.keys():
                if IIP.get(blacklist_type) in self.blacklists[blacklist_type]:
                    logging.debug("Blacklisted {} for {} : {}".format(blacklist_type, ip, IIP.get(blacklist_type)))
                    IIP.set_blacklist(blacklist_type)
            for whitelist_type in self.whitelists.keys():
                if IIP.get(whitelist_type) in self.whitelists[whitelist_type]:
                    logging.debug("Whitelisted {} for {} : {}".format(whitelist_type, ip, IIP.get(whitelist_type)))
                    IIP.set_whitelist(whitelist_type)
            return IIP
        except Exception as e:
            logging.warning("Problem inspecting ip={} : {}".format(ip, e))
            return None

    def get(self, ip):
        """For convienice switching between Inspector and MaxMind Client"""
        return self.inspect(ip)


def append_to_(list_type, iip: Inspected_IP, field='ORG', list_path=None, force=False):
    """Append to a whitelist OR blacklist.
    """

    if field not in CONFIG['default'][list_type+'s'].keys():
        logging.warning("{} type '{}' not defined in default config".format(list_type, field))

    full_path = os.path.join(WORK_DIR, CONFIG['default'][list_type+'s'][field])
    if list_path and os.path.exists(list_path):
       full_path = list_path
    if not os.path.exists(full_path):
        logging.warning("Creating {} at {}.".format(list_type, full_path))

    logging.debug("Using {} at '{}'".format(list_type, full_path))
    try:
        origional_map = iip.build_map()
        value = origional_map[field]
        if iip.is_blacklisted and list_type == 'blacklist':
            logging.warning("'{}' already defined in blacklist.".format(value))
            return None
        elif iip.is_whitelisted and list_type == 'whitelist':
            logging.warning("'{}' already defined in whitelist.".format(value))
            return None
        # By default, do not blacklist things that are whitelisted and vice versa
        if not force:
            if iip.is_whitelisted and list_type == 'blacklist':
                logging.warning("'{}' is whitelisted. Not adding to blacklist.".format(value))
                return False
            if iip.is_blacklisted and list_type == 'whitelist':
                logging.warning("'{}' is blacklisted. Not adding to whitelist.".format(value))
                return False
        logging.info("Appending '{}'  to {} {}".format(value, field, list_type))
        with open(full_path, 'a+') as l:
            l.write(value+'\n')
    except Exception as e:
        logging.error("problem appending to {}: {}".format(list_type, e))
        return False

    return True

def remove_from_(list_type, iip: Inspected_IP, field='ORG', list_path=None):
    """remove from a whitelist OR blacklist.
    """

    if field not in CONFIG['default'][list_type+'s'].keys():
        logging.warning("{} type '{}' not defined in default config".format(list_type, field))

    full_path = os.path.join(WORK_DIR, CONFIG['default'][list_type+'s'][field])
    if list_path and os.path.exists(list_path):
       full_path = list_path
    if not os.path.exists(full_path):
        logging.error("No {} file exists at {}.".format(list_type, list_path))
        return False

    logging.debug("Using {} at '{}'".format(list_type, full_path))
    try:
        with open(full_path, 'r') as l:
            current_list = l.readlines()
    except Exception as e:
        logging.error("Couldn't load current {} at {}".format(list_type, full_path))
        return False
    
    try:
        origional_map = iip.build_map()
        value = origional_map[field]
        if value+'\n' not in current_list:
            logging.warning("{} already not in {} {}.".format(value, field, list_type))
            return None
        logging.info("Removing {} from {} {}".format(value, field, list_type))
        current_list.remove(value+'\n')
        with open(full_path, 'w') as fp:
            for item in current_list:
                fp.write(item)
    except Exception as e:
        logging.error("problem deleteing from {}: {}".format(list_type, e))
        return False

    return True
