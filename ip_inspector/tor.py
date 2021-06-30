import io
import os
import sys
import time
import logging
import requests

from ip_inspector.config import load_configuration, WORK_DIR, DATA_DIR, VAR_DIR

CONFIG = load_configuration()
DOWNLOAD_URL = CONFIG['tor']['exit_node_url']
CACHE_PATH = os.path.join(WORK_DIR, CONFIG['tor']['cache_path'].format(DATA_DIR=DATA_DIR))
MAX_CACHE_AGE = CONFIG['tor']['max_cache_age']


class ExitNodes():
    """Manage access and updates to Tor exit nodes."""

    def __init__(self,
                 default_ip=CONFIG['tor']['default_ip'],
                 cache_path=CACHE_PATH,
                 max_cache_age=MAX_CACHE_AGE,
                 **requests_kwargs):
        self.cache_path = cache_path
        self.max_cache_age = max_cache_age
        self._default_ip = default_ip
        self.requests_kwargs = requests_kwargs
        #if not os.path.exists(cache_path):
        #    logging.info("Creating Tor exit node cache for the first time.")
        #    self.cache_exit_nodes()
        #self.update_cache_if_old()

    def cache_exit_nodes(self):
        """Download a copy of the current TOR exit nodes and store at cache_path."""
        r = requests.get(DOWNLOAD_URL.format(IP=self._default_ip), stream=True, **self.requests_kwargs)
        if r.status_code != 200:
            logging.error("Got {} from torproject.org".format(r.status_code))
            return False
        if os.path.exists(self.cache_path):
            os.remove(self.cache_path)
        with open(self.cache_path, 'wb') as fp:
            for chunk in r.iter_content(io.DEFAULT_BUFFER_SIZE):
                fp.write(chunk)
        if os.path.exists(self.cache_path):
            logging.debug("Cached current TOR Exit Nodes at '{}'".format(self.cache_path))
            return True
        return False

    @property
    def cache_age(self):
        """Returns the age, in hours, of the cache."""
        if not os.path.exists(self.cache_path):
            self.cache_exit_nodes()
        return (time.time() - os.path.getmtime(self.cache_path)) / 60 / 60

    def update_cache_if_old(self):
        """Update the cache if it's older than max_cache_age hours."""
        if self.cache_age >= self.max_cache_age:
            logging.debug("Updating Tor exit nodes")
            if not self.cache_exit_nodes():
                logging.warning("Problem updating cache")
                return False
            return True

    def load_exit_nodes_from_cache(self):
        """Return the current list of Tor exit nodes as a list."""
        try:
            self.update_cache_if_old()
            with open(self.cache_path, 'rb') as fp:
                exit_nodes = [line.decode('utf-8').strip() for line in fp.readlines() if not line.lstrip().startswith(b'#')]
            return exit_nodes
        except Exception as e:
            logging.warning("Problem occured reading exit nodes: {}".format(e))
            return False
    
    def load_exit_nodes_from_torproject(self):
        """Download the exit nodes directly from torproject and load them into a list."""
        try:
            r = requests.get(DOWNLOAD_URL.format(IP=self._default_ip), **self.requests_kwargs)
            if r.status_code != 200:
                logging.error("Got {} from torproject.org".format(r.status_code))
                return False
            return [line.strip() for line in r.text.splitlines() if not line.startswith('#')]
        except Exception as e:
            logging.warning("Problem getting exit nodes from torproject: {}".format(e))
            return False

    @property
    def exit_nodes(self):
        exit_nodes = self.load_exit_nodes_from_cache()
        if exit_nodes:
            return exit_nodes
        exit_nodes = self.load_exit_nodes_from_torproject()
        if exit_nodes:
            logging.debug("Using exit nodes from direct torproject pull")
            return exit_nodes
        return []

    def is_exit_node(self, ip):
        """See if this ip address is in the current list of Tor exit nodes."""
        if ip in self.exit_nodes:
            return True
        return False

