""" Proactive layer 2 Openflow Controller """

import logging
import json
import os
import sys
from urllib.request import FileHandler

from cerberus import config_parser
from cerberus.exceptions import *
from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.lib.packet import packet, ethernet, ether_types, vlan

# Flow Tables
IN_TABLE = 0
OUT_TABLE = 1

PRIORITY = 1500

DEFAULT_CONFIG = "/etc/cerberus/topology.json"
DEFAULT_LOG_PATH = "/var/log/cerberus"
DEFAULT_LOG_FILE = "/var/log/cerberus/cerberus.log"


class cerberus(app_manager.RyuApp):
    """ A RyuApp for proactively configuring layer 2 switches 

    Cerberus removes MAC learning from the switching fabric for networks where
    the topologies are known in advanced
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet}

    def __init__(self, *_args, **_kwargs):
        super(cerberus, self).__init__(*_args, **_kwargs)

        self.dpset = _kwargs['dpset']
        self.logname = 'cerberus'
        # self.logger = self.setup_logger()
        self.config = self.get_config_file()

    def get_config_file(self, config_file=DEFAULT_CONFIG):
        """ Reads config file from file and checks it's validity """
        config = self.open_config_file(config_file)
        if not config_parser.check_config(config, self.logname):
            sys.exit()

    def open_config_file(self, config_file):
        """ Reads the config """
        data = None
        try:
            with open(config_file) as json_file:
                data = json.load(json_file)
        except (UnicodeDecodeError, PermissionError, ValueError) as err:
            self.logger.error(f"Error in config file: {config_file}\n{err}")
            sys.exit()
        except (FileNotFoundError) as err:
            self.logger.error(f"File not found: {config_file}\n")
            if config_file is DEFAULT_CONFIG:
                self.logger.error(
                    f"Please specify a topology in {DEFAULT_CONFIG} or " +
                    "specify a config using the --config option")
            sys.exit()

        return data


    def setup_logger(self, loglevel=logging.INFO,
                     logfile=DEFAULT_LOG_FILE, quiet=False):
        """ Setup and return the logger """
        
        logger = logging.getLogger(self.logname)
        log_handler = logging.FileHandler(logfile)
        log_handler.setFormatter( 
            logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s', 
                              '%b %d %H:%M:%S'))
        logger.addHandler(log_handler)

        logger.setLevel(loglevel)

        return logger
