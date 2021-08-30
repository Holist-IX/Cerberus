""" Proactive layer 2 Openflow Controller """

import configparser
import logging
import json
import os
import sys

from cerberus.config_parser import Validator, Parser
from cerberus.exceptions import *
from pbr.version import VersionInfo
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
        self.logger = self.setup_logger()
        self.logger.info(f"Starting Cerberus {VersionInfo('cerberus')}")
        self.config = self.get_config_file()

    def get_config_file(self, config_file=DEFAULT_CONFIG):
        """ Reads config file from file and checks it's validity """
        # TODO: Get config file from env if set
        config = self.open_config_file(config_file)
        self.logger.info("Checking config file")
        if not Validator().check_config(config, self.logname):
            sys.exit()
        links, p4_switches, switches, group_links = Parser(self.logname).parse_config(config)
        parsed_config = {   "links": links, 
                            "p4_switches": p4_switches, 
                            "switches": switches, 
                            "group_links": group_links}
        return parsed_config
        
    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_connection_handler(self, ev):
        """ Handles connecting to switches """
        dp_id = self.format_dpid(ev.dp.id)
        if ev.enter:
            self.logger.info(f'Datapath: {dp_id} found')

            if self.datapath_to_be_configured(dp_id):
                self.logger.info(f"Datapath: {dp_id} configuring")
                self.send_flow_stats_request(ev.dp)

    def sw_already_configured(self, datapath):
        """ Helper to pull switch state and see if it has already been configured """
        pass


    def send_flow_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = []
        self.logger.info(ev.msg.body)
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                        'duration_sec=%d duration_nsec=%d '
                        'priority=%d '
                        'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                        'cookie=%d packet_count=%d byte_count=%d '
                        'match=%s instructions=%s' %
                        (stat.table_id,
                        stat.duration_sec, stat.duration_nsec,
                        stat.priority,
                        stat.idle_timeout, stat.hard_timeout, stat.flags,
                        stat.cookie, stat.packet_count, stat.byte_count,
                        stat.match, stat.instructions))
        self.logger.info('FlowStats: %s', flows)


    def first_time_sw_setup(self, datapath):
        """ Sets up the switch for the first time """
        pass


    def update_sw(self, datapath):
        """ Helper to get rules and update the rules on the switch """
        pass


    def datapath_to_be_configured(self, dp_id):
        """ Checks if the datapath needs to be configured """
        for sw in self.config['switches']:
            if dp_id == self.config['switches'][sw]['dp_id']:
                return True
        
        self.logger.error(f'Datapath: {dp_id}\t has not been configured.')
        return False


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

    def format_dpid(self, dp_id):
        """ Formats dp id to hex for consistency """
        return hex(dp_id)

    def setup_logger(self, loglevel=logging.INFO,
                     logfile=DEFAULT_LOG_FILE, quiet=False):
        """ Setup and return the logger """
        
        logger = logging.getLogger(self.logname)
        log_handler = logging.FileHandler(logfile, mode='a+')
        log_handler.setFormatter( 
            logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s', 
                              '%b %d %H:%M:%S'))
        logger.addHandler(log_handler)

        logger.setLevel(loglevel)

        return logger
