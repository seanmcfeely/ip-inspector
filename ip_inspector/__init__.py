import os
import logging

from ip_inspector.config import CONFIG, HOME_PATH
from ip_inspector import maxmind


class Inspected_IP(maxmind.MaxMind_IP):
    """A MaxMind_IP result with whitelist/blacklist metadata added."""

    def __init__(self, asn_result, city_result, country_result, blacklist_type=None, whitelist_type=None):
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
            self.map[blacklist_type] = self._blacklist_str.format(self.get(blacklist_type))
            self._blacklisted = True
        if whitelist_type:
            self.map[whitelist_type] = self._whitelist_str.format(self.get(whitelist_type))
            self._whitelisted = True

    def set_blacklist(self, blacklist_type):
        self.map[blacklist_type] = self._blacklist_str.format(self.get(blacklist_type))
        self.blacklist_reason = blacklist_type
        self._blacklisted = True

    def set_whitelist(self, whitelist_type):
        self.map[whitelist_type] = self._whitelist_str.format(self.get(whitelist_type))
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


class Inspector():
    """An a computer network inspector for the primary purpose of
       Intel & Detection. Wrapper around maxmind.Client.

    :intel_agents: API objects to query for resources.
    :blacklists: Detection files.
    :whitelists: good guys.
    """

    def __init__(self,
                 mmc: maxmind.Client,
                 blacklists=CONFIG['default']['blacklists'],
                 whitelists=CONFIG['default']['whitelists']
                 ):
       
        self.mmc = mmc
        self.blacklists = {}
        self.whitelists = {}
        for bl_type, bl_path in blacklists.items():
            full_path = bl_path
            if not os.path.exists(full_path):
                full_path = os.path.join(HOME_PATH, full_path)
                if not os.path.exists(full_path):
                    logging.debug("No {} blacklist found at {} or {}".format(bl_type, bl_path, full_path))
                    continue
            with open(full_path, 'r') as fp:
                self.blacklists[bl_type] = [line.strip() for line in fp.readlines()]
        for wl_type, wl_path in whitelists.items():
            full_path = wl_path
            if not os.path.exists(full_path):
                full_path = os.path.join(HOME_PATH, full_path)
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
            IIP = Inspected_IP(self.mmc.asn(ip), self.mmc.city(ip), self.mmc.country(ip))
            for blacklist_type in self.blacklists.keys():
                if IIP.get(blacklist_type) in self.blacklists[blacklist_type]:
                    logging.debug("Blacklisted {} for {} : {}".format(blacklist_type, ip, IIP.get(blacklist_type)))
                    IIP.set_blacklist(blacklist_type)
            for whitelist_type in self.whitelists.keys():
                if IIP.get(whitelist_type) in self.whitelists[whitelist_type]:
                    logging.debug("Blacklisted {} for {} : {}".format(whitelist_type, ip, IIP.get(whitelist_type)))
                    IIP.set_whitelist(whitelist_type)
            return IIP
        except Exception as e:
            logging.warning("Problem inspecting ip={} : {}".format(ip, e))
            return None

    def get(self, ip):
        """For convienice switching between Inspector and MaxMind Client"""
        return self.inspect(ip)
