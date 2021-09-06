""" Proactive layer 2 Openflow Controller """

from array import array
from ast import Dict
from collections import defaultdict
import logging
import json
import os
import sys
from tokenize import Number
from urllib import request

from cerberus.config_parser import Validator, Parser
from cerberus.exceptions import *
from pbr.version import VersionInfo
from ryu.base import app_manager
from ryu.controller import ofp_event, dpset, controller
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.lib.packet import packet, ethernet, ether_types, vlan

# Flow Tables
IN_TABLE = 0
OUT_TABLE = 1

DEFAULT_PRIORITY = 1500

DEFAULT_CONFIG = "/etc/cerberus/topology.json"
DEFAULT_LOG_PATH = "/var/log/cerberus"
DEFAULT_LOG_FILE = "/var/log/cerberus/cerberus.log"
DEFAULT_COOKIE = 525033

FLOW_NOT_FOUND = 0
FLOW_EXISTS = 1
FLOW_TO_UPDATE = 2


class cerberus(app_manager.RyuApp):
    """ A RyuApp for proactively configuring layer 2 switches 

    Cerberus removes MAC learning from the switching fabric for networks where
    the topologies are known in advanced
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet}

    def __init__(self, cookie=DEFAULT_COOKIE, *_args, **_kwargs):
        super(cerberus, self).__init__(*_args, **_kwargs)

        self.dpset = _kwargs['dpset']
        self.logname = 'cerberus'
        self.logger = self.setup_logger()
        self.logger.info(f"Starting Cerberus {VersionInfo('cerberus')}")
        self.hashed_config = None
        self.config = self.get_config_file()
        self.cookie = cookie

    def get_config_file(self, config_file=DEFAULT_CONFIG):
        """ Reads config file from file and checks it's validity """
        # TODO: Get config file from env if set
        conf_parser = Parser(self.logname)
        config = self.open_config_file(config_file)
        self.logger.info("Checking config file")
        if not Validator().check_config(config, self.logname):
            sys.exit()
        new_hashed_config = conf_parser.get_hash(config)
        if self.hashed_config:
            if new_hashed_config == self.hashed_config and self.config:
                return self.config
            # TODO pull rules and compare the differences
        self.hashed_config = conf_parser.get_hash(config)
        links, p4_switches, switches, group_links = conf_parser.parse_config(config)
        print(switches)
        print('group_links')
        print(group_links)
        dp_id_to_sw = self.associate_dp_id_to_swname(switches)
        parsed_config = {"links": links,
                         "p4_switches": p4_switches,
                         "switches": switches,
                         "group_links": group_links,
                         "dp_id_to_sw_name": dp_id_to_sw}
        return parsed_config

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_connection_handler(self, ev):
        """ Handles connecting to switches """
        dp_id = self.format_dpid(ev.dp.id)
        if ev.enter:
            self.logger.info(f'Datapath: {dp_id} found')

            if self.datapath_to_be_configured(dp_id):
                self.logger.info(f"Datapath: {dp_id} to be configured")
                self.send_flow_stats_request(ev.dp)

    def sw_already_configured(self, datapath: controller.Datapath, flows: list):
        """ Helper to pull switch state and see if it has already been configured """
        conf_parser = Parser(self.logname)
        dp_id = datapath.id
        sw_name = self.config['dp_id_to_sw_name'][dp_id]
        for port, hosts in self.config['switches'][sw_name]['hosts'].items():
            print(port)
            print(hosts)
            for host in hosts:
                self.check_if_host_in_flows(datapath, host, port, flows, direct=True)
        


    def send_flow_stats_request(self, datapath):
        ofp_parser: ofproto_v1_3_parser
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = []
        dp: controller.Datapath
        dp = ev.msg.datapath
        dp_id = dp.id
        stat: ofproto_v1_3_parser.OFPFlowStats
        for stat in ev.msg.body:
            # flows.append('table_id=%s '
            #              'duration_sec=%d duration_nsec=%d '
            #              'priority=%d '
            #              'idle_timeout=%d hard_timeout=%d flags=0x%04x '
            #              'cookie=%d packet_count=%d byte_count=%d '
            #              'match=%s instructions=%s' %
            #              (stat.table_id,
            #               stat.duration_sec, stat.duration_nsec,
            #               stat.priority,
            #               stat.idle_timeout, stat.hard_timeout, stat.flags,
            #               stat.cookie, stat.packet_count, stat.byte_count,
            #               stat.match, stat.instructions))
            flow = {"table_id": stat.table_id, "match": stat.match, 
                    "instructions": stat.instructions, "cookie": stat.cookie}
            flows.append(flow)
        self.logger.info(f"Datapath: {dp_id}\t FlowStats: {flows}")
        if len([f for f in flows if f['cookie'] == self.cookie]) < 1:
            self.logger.info(f"Datapath {dp_id} will be configured")
            self.clear_flows(dp)
            self.full_sw_setup(dp)
        else:
            self.sw_already_configured(dp, flows)
        

    def full_sw_setup(self, datapath):
        """ Sets up the switch for the first time """
        dp_id = datapath.id
        self.setup_groups(datapath)
        self.setup_sw_hosts(datapath)
        self.logger.info(f"Datapath: {dp_id} configured")

    def setup_sw_hosts(self, datapath):
        """ Sets up the in table for the datapath """
        dp_id = datapath.id
        for switch in self.config['switches']:
            print(f"Printing  switch: {switch}")
            if self.format_dpid(dp_id) != self.config['switches'][switch]['dp_id']:
                group_id = self.config['switches'][switch]['dp_id']
                self.setup_flows_for_not_direct_connections(datapath, switch, int(group_id))
                continue
            for port, hosts in self.config['switches'][switch]['hosts'].items():
                for host in hosts:
                    host_name = host['name']
                    mac = host['mac']
                    vlan_id = host['vlan'] if 'vlan' in host else None
                    tagged = host['tagged'] if 'tagged' in host else None
                    ipv4 = host['ipv4'] if 'ipv4' in host else None
                    ipv6 = host['ipv6'] if 'ipv6' in host else None
                    self.logger.info(f"Datapath: {dp_id}\tConfiguring host: " +
                                     f"{host_name} on port: {port}")
                    self.logger.debug(f"Datapath: {dp_id}\t host: {host_name} "+
                                      f"has mac: {mac}\tvlan: {vlan_id}\t" + 
                                      f"tagged: {tagged}\tipv4: {ipv4}\t" + 
                                      f"ipv6: {ipv6}")
                    self.add_in_flow(port, datapath, mac, vlan_id, tagged)
                    self.setup_flows_for_direct_connect(datapath, port, 
                                                        host_name, mac, vlan_id,
                                                        tagged, ipv4, ipv6)

    def setup_flows_for_direct_connect(self, datapath, port, host_name, mac, 
                                       vlan_id, tagged, ipv4, ipv6):
        """ Sets up the flows for hosts directly connected to the switch """
        # dp_id = datapath.id
        self.add_direct_mac_flow(datapath, host_name, mac, vlan_id, 
                                 tagged, port)
        self.add_direct_ipv4_flow(datapath, host_name, mac, ipv4, vlan_id, 
                                  tagged, port)
        self.add_direct_ipv6_flow(datapath, host_name, mac, ipv6, vlan_id,
                                  tagged, port)


    def setup_flows_for_not_direct_connections(self, datapath, switch, group_id):
        """ Sets up the flows for hosts not directly connected to the switch """

        for _, hosts in self.config['switches'][switch]['hosts'].items():
                for host in hosts:
                    host_name = host['name']
                    mac = host['mac']
                    vlan_id = host['vlan'] if 'vlan' in host else None
                    ipv4 = host['ipv4'] if 'ipv4' in host else None
                    ipv6 = host['ipv6'] if 'ipv6' in host else None
                    self.add_indirect_mac_flow(datapath, host_name, mac, 
                                               vlan_id, group_id)
                    self.add_indirect_ipv4_flow(datapath, host_name, mac, ipv4,
                                                vlan_id, group_id)
                    self.add_indirect_ipv6_flow(datapath, host_name, mac, ipv6, 
                                                vlan_id, group_id)

    def setup_groups(self, datapath):
        """ Initial setup of the groups on the switch """
        isolated_switches = Parser(self.logname).find_isolated_switches(self.config['group_links'])
        group_links = self.config['group_links']
        switches = self.config['switches']
        links = self.config['links']
        
        for sw in group_links:
            self.setup_core_in_table(datapath, sw)
            if sw in isolated_switches:
                for other_sw in [s for s in group_links if s == sw]:
                    group_id = int(switches[other_sw]['dp_id'])
                    link = self.config['group_links'][sw]
                    self.build_group(datapath, link, int(group_id))
                continue
            for other_sw, details in switches.items():
                if other_sw == sw:
                    continue
                target_dp_id = details['dp_id']
                if target_dp_id in group_links[sw]:
                    sw_link = group_links[sw][target_dp_id]
                    l = [sw, sw_link['main'],
                            sw_link['other_sw'], sw_link['other_port']]
                    new_links = self.remove_old_link_for_ff(l, links)

                    self.find_group_rule(datapath, new_links, sw, sw_link, 
                                            other_sw, group_links, target_dp_id)
                else:
                    route = self.find_route(links, sw, other_sw)
                    
                    if route:
                        sw_link = group_links[sw][target_dp_id]
                        next_hop_id = switches[route[1]]['dp_id']
                        out_port = group_links[sw][next_hop_id]['main']
                        group_links[sw][target_dp_id] = { 
                            "main": out_port,
                            "other_sw": route[1],
                            "other_port": group_links[sw][next_hop_id]['other_port']
                        }
                        new_links = list(links)

                        li = [sw, group_links[sw][target_dp_id]['main'],
                              group_links[sw][target_dp_id]['other_sw'],
                              group_links[sw][target_dp_id]['other_port']]
                        
                        new_links = self.remove_old_link_for_ff(li, links)

                        self.find_group_rule(datapath, new_links, sw, sw_link, 
                                             other_sw, group_links, target_dp_id)


    def build_group(self, datapath: controller.Datapath, link: dict, group_id):
        """ build the groups rule to send to the switch """
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
        main_port = int(link['main'])
        main_actions = [ofproto_parser.OFPActionOutput(main_port)]
        buckets = [ofproto_parser.OFPBucket(watch_port=main_port, 
                                            actions=main_actions)]
        if 'backup' in link:
            backup_port = int(link['backup'])
            backup_actions = [ofproto_parser.OFPActionOutput(backup_port)]
            buckets.append(ofproto_parser.OFPBucket(watch_port=backup_port,
                                            actions=backup_actions))
        
        print(f"Group id = {group_id}")
        msg = ofproto_parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, 
                                         ofproto.OFPGT_FF, int(group_id), buckets)

        datapath.send_msg(msg)

    def add_direct_mac_flow(self, datapath, host_name, mac, vid, tagged, port,
                            priority=DEFAULT_PRIORITY, cookie=DEFAULT_COOKIE):
        """ Add mac flow for directly connected host """
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = []
        match = ofproto_parser.OFPMatch(vlan_vid=(ofproto.OFPVID_PRESENT | vid),
                                        eth_dst=mac)
        if not tagged:
            actions.append(ofproto_parser.OFPActionPopVlan())
        actions.append(ofproto_parser.OFPActionOutput(port))
        instructions = [ofproto_parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            actions)]
        
        self.add_flow(datapath, match, instructions, OUT_TABLE, cookie, priority)


    def build_direct_mac_flow_out(self, datapath: controller.Datapath, mac, vid, 
                                  tagged, port, priority=DEFAULT_PRIORITY):
        """ Builds match and instructions for the out table for mac of hosts
            that are directly connected """
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser
        match = None
        instructions = []

        actions = []
        match = ofproto_parser.OFPMatch(vlan_vid=(ofproto.OFPVID_PRESENT | vid),
                                        eth_dst=mac)
        if not tagged:
            actions.append(ofproto_parser.OFPActionPopVlan())
        actions.append(ofproto_parser.OFPActionOutput(port))
        instructions = [ofproto_parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            actions)]
        
        return match, instructions

    def build_direct_mac_flow_in(self, datapath: controller.Datapath, mac, vid, 
                              tagged, port, priority=DEFAULT_PRIORITY):
        """ Builds match and instructions for the in table for mac of hosts that
            are directly connected"""
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser
        match = None
        instructions = []
        if tagged:
            match = ofproto_parser.OFPMatch(in_port=port, 
                        vlan_vid=(ofproto.OFPVID_PRESENT | vid),
                        eth_src=mac)
        else:
            match = ofproto_parser.OFPMatch(in_port=port, eth_src=mac)
            tag_vlan_actions = [
                ofproto_parser.OFPActionPushVlan(),
                ofproto_parser.OFPActionSetField(
                    vlan_vid=(ofproto.OFPVID_PRESENT | vid))]

            actions = ofproto_parser.OFPInstructionActions(
                                ofproto.OFPIT_APPLY_ACTIONS,
                                tag_vlan_actions)
            instructions.append(actions)
        
        instructions.append(ofproto_parser.OFPInstructionGotoTable(OUT_TABLE))
        
        return match, instructions


    def add_direct_ipv4_flow(self, datapath, host_name, mac, ipv4, vid, tagged, 
                             port, priority=DEFAULT_PRIORITY, 
                             cookie=DEFAULT_COOKIE):
        """ Add ipv4 arp rule for directly connected host """
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = []
        match = ofproto_parser.OFPMatch(vlan_vid=(ofproto.OFPVID_PRESENT | vid),
                                        eth_type=ether_types.ETH_TYPE_ARP,
                                        arp_tpa=self.clean_ip_address(ipv4))
        if not tagged:
            actions.append(ofproto_parser.OFPActionPopVlan())
        actions.append(ofproto_parser.OFPActionSetField(eth_dst=mac))
        actions.append(ofproto_parser.OFPActionOutput(port))
        
        instructions = [ofproto_parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            actions)]
        self.add_flow(datapath, match, instructions, OUT_TABLE, cookie, priority)


    def add_direct_ipv6_flow(self, datapath, host_name, mac, ipv6, vid, tagged, 
                             port, priority=DEFAULT_PRIORITY, 
                             cookie=DEFAULT_COOKIE):
        """ Add ipv6 arp rule for directly connected host """
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = []
        # "icmpv6_type": 135, "ip_proto": 58, "eth_type": 34525
        match = ofproto_parser.OFPMatch(vlan_vid=(ofproto.OFPVID_PRESENT | vid),
                                    icmpv6_type=135, ip_proto=58, 
                                    eth_type=34525, 
                                    ipv6_nd_target=self.clean_ip_address(ipv6))
        if not tagged:
            actions.append(ofproto_parser.OFPActionPopVlan())
        actions.append(ofproto_parser.OFPActionSetField(eth_dst=mac))
        actions.append(ofproto_parser.OFPActionOutput(port))
        
        instructions = [ofproto_parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            actions)]
        self.add_flow(datapath, match, instructions, OUT_TABLE, cookie, priority)


    def add_indirect_mac_flow(self, datapath, host_name, mac, vid, group_id, 
                              priority=DEFAULT_PRIORITY, cookie=DEFAULT_COOKIE):
        """ Add mac rule for indirectly connected hosts """
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        match, instructions = self.build_indirect_mac_flow_out(datapath, mac, 
                                                          vid, group_id)

        # match = ofproto_parser.OFPMatch(vlan_vid=(ofproto.OFPVID_PRESENT | vid),
        #                                 eth_dst=mac)

        # instructions = [ofproto_parser.OFPInstructionActions(
        #                     ofproto.OFPIT_APPLY_ACTIONS,
        #                     [ofproto_parser.OFPActionGroup(group_id)])]

        self.add_flow(datapath, match, instructions, OUT_TABLE, cookie, priority)


    def build_indirect_mac_flow_out(self, datapath: controller.Datapath, mac, 
                                    vid, group_id):
        """ Builds the flow and instructions for mac flows of hosts 
            inderectly connected """
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser
        match = None
        instructions = []

        match = ofproto_parser.OFPMatch(vlan_vid=(ofproto.OFPVID_PRESENT | vid),
                                        eth_dst=mac)

        instructions = [ofproto_parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            [ofproto_parser.OFPActionGroup(group_id)])]

        return match, instructions

    def add_indirect_ipv4_flow(self, datapath, host_name, mac, ipv4, vid, 
                               group_id, priority=DEFAULT_PRIORITY, 
                               cookie=DEFAULT_COOKIE):
        """ Add ipv4 rule for inderectly connected hosts """
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        match = ofproto_parser.OFPMatch(vlan_vid=(ofproto.OFPVID_PRESENT | vid),
                                        eth_type=ether_types.ETH_TYPE_ARP,
                                        arp_tpa=self.clean_ip_address(ipv4))

        instructions = [ofproto_parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            [ofproto_parser.OFPActionSetField(eth_dst=mac),
                             ofproto_parser.OFPActionGroup(group_id)])]

        self.add_flow(datapath, match, instructions, OUT_TABLE, cookie, priority)


    
    def add_indirect_ipv6_flow(self, datapath, host_name, mac, ipv6, vid, 
                               group_id, priority=DEFAULT_PRIORITY, 
                               cookie=DEFAULT_COOKIE):
        """ Add ipv6 rule for inderectly connected hosts """
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        match = ofproto_parser.OFPMatch(vlan_vid=(ofproto.OFPVID_PRESENT | vid),
                                        icmpv6_type=135, ip_proto=58, 
                                        eth_type=34525, 
                                        ipv6_nd_target=self.clean_ip_address(ipv6))

        instructions = [ofproto_parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            [ofproto_parser.OFPActionSetField(eth_dst=mac),
                             ofproto_parser.OFPActionGroup(group_id)])]

        self.add_flow(datapath, match, instructions, OUT_TABLE, cookie, priority)


    def add_in_flow(self, port, datapath, mac=None, vlan=None, tagged=False, 
                    priority=DEFAULT_PRIORITY, cookie=DEFAULT_COOKIE):
        """ Constructs flow for in table """
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = None
        actions = []
        if mac:
            # if tagged:
            #     match = ofproto_parser.OFPMatch(in_port=port, 
            #                 vlan_vid=(ofproto.OFPVID_PRESENT | vlan),
            #                 eth_src=mac)
            # else:
            #     match = ofproto_parser.OFPMatch(in_port=port, eth_src=mac)
            #     tag_vlan_actions = [
            #         ofproto_parser.OFPActionPushVlan(),
            #         ofproto_parser.OFPActionSetField(
            #             vlan_vid=(ofproto.OFPVID_PRESENT | vlan))]

            #     instructions = ofproto_parser.OFPInstructionActions(
            #                         ofproto.OFPIT_APPLY_ACTIONS,
            #                         tag_vlan_actions)
            #     actions.append(instructions)
            match, actions = self.build_direct_mac_flow_in(datapath, mac, vlan, 
                                                           tagged, port, 
                                                           priority)
        else:
            match = ofproto_parser.OFPMatch(in_port=port)
            actions.append(ofproto_parser.OFPInstructionGotoTable(OUT_TABLE))
        self.add_flow(datapath, match, actions, IN_TABLE, cookie, priority)

    def add_flow(self, datapath, match, actions, table, cookie=DEFAULT_COOKIE, 
                 priority=DEFAULT_PRIORITY):
        """ Helper to a flow to the switch """
        parser = datapath.ofproto_parser
        flow_mod = parser.OFPFlowMod(datapath=datapath, match=match, 
                                     instructions=actions, table_id=table, 
                                     priority=priority, cookie=cookie)
        
        datapath.send_msg(flow_mod)


    def update_sw(self, datapath):
        """ Helper to get rules and update the rules on the switch """
        pass

    def remove_old_link_for_ff(self, link_to_remove, links):
        """ Removes a local link to generate a topology with that link down and 
            determine which paths to take for redundancy """
        new_links = list(links)
        if link_to_remove in new_links:
            new_links.remove(link_to_remove)
            return new_links
        li = [link_to_remove[2], link_to_remove[3], 
              link_to_remove[0], link_to_remove[1]]
        try:
            new_links.remove(li)
        except:
            self.logger.error("Error trying to remove link from the core.")
            self.logger.error(f"Link to remove: {str(link_to_remove)}")
            self.logger.error(f"Link Array: {str(links)}")
        return new_links


    def find_group_rule(self, datapath, links, sw, sw_link, target_sw, 
                        group_links, group_id):
        """ Find the path between 2 switches and create links for them """
        route = self.find_route(links, sw, target_sw)
        if route:
            backup = [v['main'] for k,v in group_links[sw].items() if route[1] == v['other_sw']]
            sw_link['backup'] = str(backup[0])

        self.build_group(datapath, sw_link, group_id)


    def find_route(self, links, source_sw, target_sw):
        """ Helper method to return a route between two switches """
        link_nodes = self.spf_organise(links)
        spfgraph = Graph()
        for node in link_nodes:
            spfgraph.add_edge(*node)
        route = self.dijkstra(spfgraph, source_sw, target_sw)
        return route


    def setup_core_in_table(self, datapath, switch):
        """ Initial setup flows for in table """
        for _, link in self.config['group_links'][switch].items():
            port = int(link['main'])
            self.add_in_flow(datapath=datapath, port=port)


    def datapath_to_be_configured(self, dp_id):
        """ Checks if the datapath needs to be configured """
        for sw in self.config['switches']:
            if dp_id == self.config['switches'][sw]['dp_id']:
                return True

        self.logger.warning(f'Datapath: {dp_id}\t has not been configured.')
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

    def clean_ip_address(self, address):
        """ Cleans address if an address range is found """
        if "/" in address:
            clean_address = address.split('/')[0]
            return clean_address
        return address

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

    def check_if_host_in_flows(self, datapath, host, port, flows, direct=True):
        """ Helper function to see if a host exists on the switch """
        host_name = host['name']
        mac = host['mac']
        vlan_id = host['vlan'] if 'vlan' in host else None
        tagged = host['tagged'] if 'tagged' in host else None
        ipv4 = host['ipv4'] if 'ipv4' in host else None
        ipv6 = host['ipv6'] if 'ipv6' in host else None

        result = self.check_if_mac_flow_exists(datapath, mac, vlan_id, tagged, port, 
                                               flows, direct)


    def check_if_mac_flow_exists(self, datapath, mac, vlan_id, tagged, port, 
                                 flows, group_id=None):
        """ Checks to see if the mac address exists in the flow table """
        exists = FLOW_NOT_FOUND
        if not group_id:
            in_match, in_inst = self.build_direct_mac_flow_in(datapath, mac, 
                                                              vlan_id, tagged, 
                                                              port)
            in_flows = [f for f in flows if f.table_id == IN_TABLE]
            exists, flow = self.check_if_flow_and_instructions_match(in_flows, 
                                                        in_match, in_inst)
            if exists != FLOW_EXISTS:
                return exists, flows
            flows.remove(flow)
    
            out_match, out_inst = self.build_direct_mac_flow_out(datapath, mac,
                                                        vlan_id, tagged, port)
        else:
            out_match, out_inst = self.build_indirect_mac_flow_out(datapath, mac,
                                                            vlan_id, group_id)
        
        out_flows = [f for f in flows if f.table_d == OUT_TABLE]

        exists, flow = self.check_if_flow_and_instructions_match(out_flows, 
                                                        out_match, out_inst)
        if exists != FLOW_EXISTS:
            return exists, flows
        flows.remove(flow)
        return exists, flows


    def check_if_flow_and_instructions_match(self, flows, match, instructions):
        """ Helper to see if a generated flow matches a pulled one """
        exists = FLOW_NOT_FOUND
        for flow in flows:
            if match in flow['match'] and instructions in flow['instructions']:
                exists = FLOW_EXISTS
                return exists, flow
            if match in flow['match'] or instructions in flow['instructions']:
                exists = FLOW_TO_UPDATE
                return exists, flow
        return exists, None

    def associate_dp_id_to_swname(self, switches):
        """ Sets up dictionary to simplify retreiving a switch name when only 
            having a dpid """
        
        dp_id_to_swname = {}
        for switch in switches:
            dp_id = switches[switch]['dp_id']
            dp_id_to_swname[dp_id] = switch
        return dp_id_to_swname


    def format_dpid(self, dp_id):
        """ Formats dp id to int for consistency """
        return int(dp_id)

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


    def spf_organise(self, links):
        """ Organises the links so that can be used for the shortest path """
        link_nodes = []
        for link in links:
            cost = 1000
            link_nodes.append([link[0], link[2], cost])
        return link_nodes


    def dijkstra(self, graph, initial, end):
        """ Dijkstra's algorithm used to determine shortest path """
        # shortest paths is a dict of nodes
        # whose value is a tuple of (previous node, weight)
        shortest_paths = {initial: (None, 0)}
        current_node = initial
        visited = set()

        while current_node != end:
            visited.add(current_node)
            destinations = graph.edges[current_node]
            weight_to_current_node = shortest_paths[current_node][1]

            for next_node in destinations:
                weight = graph.weights[(
                    current_node, next_node)] + weight_to_current_node
                if next_node not in shortest_paths:
                    shortest_paths[next_node] = (current_node, weight)
                else:
                    current_shortest_weight = shortest_paths[next_node][1]
                    if current_shortest_weight > weight:
                        shortest_paths[next_node] = (current_node, weight)

            next_destinations = {
                node: shortest_paths[node] for node in shortest_paths
                if node not in visited}
            if not next_destinations:
                return None
            # next node is the destination with the lowest weight
            current_node = min(next_destinations,
                               key=lambda k: next_destinations[k][1])

        # Work back through destinations in shortest path
        path = []
        while current_node is not None:
            path.append(current_node)
            next_node = shortest_paths[current_node][0]
            current_node = next_node
        # Reverse path
        path = path[::-1]
        return path

class Graph():
    """ Graphs all possible next nodes from a node """
    def __init__(self):
        """
        self.edges is a dict of all possible next nodes
        e.g. {'X': ['A', 'B', 'C', 'E'], ...}
        self.weights has all the weights between two nodes,
        with the two nodes as a tuple as the key
        e.g. {('X', 'A'): 7, ('X', 'B'): 2, ...}
        """
        self.edges = defaultdict(list)
        self.weights = {}

    def add_edge(self, from_node, to_node, weight):
        """ Adds a new edge to existing node """
        # Note: assumes edges are bi-directional
        self.edges[from_node].append(to_node)
        self.edges[to_node].append(from_node)
        self.weights[(from_node, to_node)] = weight
        self.weights[(to_node, from_node)] = weight