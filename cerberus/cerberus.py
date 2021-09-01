""" Proactive layer 2 Openflow Controller """

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
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, vlan

# Flow Tables
IN_TABLE = 0
OUT_TABLE = 1

DEFAULT_PRIORITY = 1500

DEFAULT_CONFIG = "/etc/cerberus/topology.json"
DEFAULT_LOG_PATH = "/var/log/cerberus"
DEFAULT_LOG_FILE = "/var/log/cerberus/cerberus.log"
DEFAULT_COOKIE = 525033


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
        links, p4_switches, switches, group_links = Parser(
            self.logname).parse_config(config)
        print(switches)
        print('group_links')
        print(group_links)
        parsed_config = {"links": links,
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
        dp_id = ev.msg.datapath.id
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
        self.logger.info(f'Datapath: {dp_id}\t FlowStats: {flows}')
        self.clear_flows(ev.msg.datapath)
        self.full_sw_setup(ev.msg.datapath)

    def full_sw_setup(self, datapath):
        """ Sets up the switch for the first time """
        dp_id = datapath.id
        self.setup_in_table(datapath)
        # self.setup_out_table(datapath)
        # self.setup_groups(datapath)
        self.logger.info(f"Datapath: {dp_id} configured")
        pass

    def setup_in_table(self, datapath):
        """ Sets up the in table for the datapath """
        dp_id = datapath.id
        for switch in self.config['switches']:
            print(f"Printing  switch: {switch}")
            if self.format_dpid(dp_id) != self.config['switches'][switch]['dp_id']:
                continue
            for port, hosts in self.config['switches'][switch]['hosts'].items():
                for host in hosts:
                    self.logger.info(f"Datapath: {dp_id}\tConfiguring host: " +
                                     f"{host['name']} on port: {port}")
                    self.logger.debug(f"Datapath: {dp_id}\t host: "+ 
                                      f"{host['name']} has mac: {host['mac']}" +
                                      f"\tvlan: {host['vlan']}\ttagged: " + 
                                      f"{host['tagged']}")
                    self.add_in_flow(port, datapath, host['mac'], 
                                     host['vlan'], host['tagged'])
        

    def add_in_flow(self, port, datapath, mac=None, vlan=None, tagged=False, 
                    priority=DEFAULT_PRIORITY, cookie=DEFAULT_COOKIE):
        """ Constructs flow for in table """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = None
        actions = []
        if mac:
            if tagged:
                match = parser.OFPMatch(in_port=port, 
                                        vlan_vid=(ofproto.OFPVID_PRESENT | vlan),
                                        eth_src=mac)
            else:
                match = parser.OFPMatch(in_port=port, eth_src=mac)
                tag_vlan_actions = [
                    parser.OFPActionPushVlan(),
                    parser.OFPActionSetField(vlan_vid=(ofproto.OFPVID_PRESENT | vlan))]

                instructions = parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    tag_vlan_actions)
                actions.append(instructions)
        else:
            match = parser.OFPMatch(in_port=port)
        actions.append(parser.OFPInstructionGotoTable(OUT_TABLE))
        self.add_flow(datapath, priority, match, actions, IN_TABLE, cookie)

    def add_flow(self, datapath, priority, match, actions, table, cookie=DEFAULT_COOKIE):
        """ Helper to a flow to the switch """
        parser = datapath.ofproto_parser
        flow_mod = parser.OFPFlowMod(datapath=datapath, match=match, 
                                     instructions=actions, table_id=table, 
                                     priority=priority, cookie=cookie)
        
        datapath.send_msg(flow_mod)


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


    def clear_flows(self, datapath):
        """ Resets the flows on the datapath """
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
        flow_mod = ofproto_parser.OFPFlowMod(datapath=datapath, 
                                             command=ofproto.OFPFC_DELETE,
                                             table_id=ofproto.OFPTT_ALL,
                                             out_port=ofproto.OFPP_ANY,
                                             out_group=ofproto.OFPG_ANY
                                             )
        datapath.send_msg(flow_mod)

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
