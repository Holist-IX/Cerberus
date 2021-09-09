""" Proactive layer 2 Openflow Controller """

from collections import defaultdict
import logging
import json
import os
import shutil
import sys

from cerberus.config_parser import Validator, Parser
from cerberus.exceptions import *
from datetime import datetime
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
DEFAULT_ROLLBACK_DIR = "/etc/cerberus/rollback"
DEFAULT_FAILED_CONF_DIR = "/etc/cerberus/failed"
DEFAULT_COOKIE = 525033

FLOW_NOT_FOUND = 0
FLOW_EXISTS = 1
FLOW_TO_UPDATE = 2
FLOW_OLD_DELETE = 3

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

    def get_config_file(self, config_file: str = DEFAULT_CONFIG, 
                        rollback_directory: str = DEFAULT_ROLLBACK_DIR,
                        failed_directory: str = DEFAULT_FAILED_CONF_DIR):
        """ Reads config file from file and checks it's validity """
        # TODO: Get config file from env if set
        conf_parser = Parser(self.logname)
        config = self.open_config_file(config_file)
        self.logger.info("Checking config file")
        if not Validator().check_config(config, self.logname):
            self.copy_failed_config_to_failed_dir(config_file, failed_directory)
            self.logger.error(f"Restart cerberus with a valid config. A copy " +
                              f"of the failed config has been stored in " + 
                              f"{failed_directory}")
            if self.rollback_files_exist(rollback_directory):
                self.logger.error(f"Potential rollback files have been found " +
                                  f"in {rollback_directory}")
            sys.exit()
        new_hashed_config = conf_parser.get_hash(config)
        prev_config = self.get_rollback_running_config(rollback_directory)
        if prev_config:
            old_conf_hash = conf_parser.get_hash(prev_config)
            if old_conf_hash != new_hashed_config:
                self.store_rollbacks(config_file, rollback_directory)
        else:
            self.store_rollbacks(config_file, rollback_directory)
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
                self.send_group_desc_stats_request(ev.dp)

    def sw_already_configured(self, datapath: controller.Datapath, flows: list):
        """ Helper to pull switch state and see if it has already been configured """
        conf_parser = Parser(self.logname)
        dp_id = datapath.id
        sw_name = self.config['dp_id_to_sw_name'][dp_id]

        for switch in self.config['switches']:
            group_id = None
            if switch != sw_name:
                group_id = self.config['switches'][switch]['dp_id']
            for port, hosts in self.config['switches'][switch]['hosts'].items():
                for host in hosts:
                    flows = self.check_if_host_in_flows(datapath, host,
                                                        port, flows, group_id)


    def send_group_desc_stats_request(self, datapath: controller.Datapath):
        """ Sends request to datapath for its group stats """
        ofp_parser: ofproto_v1_3_parser
        ofp_parser = datapath.ofproto_parser
        ofp: ofproto_v1_3
        ofp = datapath.ofproto

        req = ofp_parser.OFPGroupDescStatsRequest(datapath, 0)

        datapath.send_msg(req)


    def send_flow_stats_request(self, datapath: controller.Datapath):
        """ Sends request to the datapath for its group stats """
        ofp_parser: ofproto_v1_3_parser
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER) #type: ignore
    def flow_stats_reply_handler(self, ev):
        """ Processes the flow stats from the datapath """
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
        self.logger.debug(f"Datapath: {dp_id}\t FlowStats: {flows}")
        if len([f for f in flows if f['cookie'] == self.cookie]) < 1:
            self.logger.info(f"Datapath {dp_id} will be configured")
            self.clear_flows(dp)
            self.full_sw_setup(dp)
        else:
            self.sw_already_configured(dp, flows)

    @set_ev_cls(ofp_event.EventOFPGroupDescStatsReply, MAIN_DISPATCHER) #type: ignore
    def group_desc_stat_reply_handler(self, ev):
        """ Processes the group stats """
        groups = []
        dp: controller.Datapath
        dp = ev.msg.datapath
        dp_id = dp.id
        stat: ofproto_v1_3_parser.OFPGroupDescStats
        for stat in ev.msg.body:
            groups.append({"group_id": stat.group_id, "buckets": stat.buckets})
        self.logger.info(f"Datapath: {dp_id} Groups: {groups}")

        if len(groups) < 1:
            self.setup_groups(dp)
        else:
            self.compare_and_update_groups(dp, groups)


    def full_sw_setup(self, datapath):
        """ Sets up the switch for the first time """
        dp_id = datapath.id
        # Assume that a switch with no flows have no groups
        # Groups needed for making group rules
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
        dp_name = self.config['dp_id_to_sw_name'][datapath.id]

        self.setup_core_in_table(datapath, dp_name)
        if dp_name in isolated_switches:
            for other_sw in [s for s in group_links if s != dp_name]:
                group_id = int(switches[other_sw]['dp_id'])
                link = self.config['group_links'][dp_name]
                self.add_group(datapath, link, int(group_id))
            return
        for other_sw, details in switches.items():
            if other_sw == dp_name:
                continue
            target_dp_id = details['dp_id']
            if target_dp_id in group_links[dp_name]:
                sw_link = group_links[dp_name][target_dp_id]
                sw_link = self.find_link_backup_group(dp_name, sw_link,
                                                        links, group_links)

                self.add_group(datapath, sw_link, target_dp_id)

            else:
                route = self.find_route(links, dp_name, other_sw)

                if route:
                    sw_link = self.find_indirect_group(self, dp_name, route,
                                links, group_links, target_dp_id, switches)

                    self.add_group(datapath, sw_link, target_dp_id)


    def find_link_backup_group(self, sw, link, links, group_links):
        """ Help to fill out group details for switches directly connected """
        other_sw = link['other_sw']
        l = [sw, link['main'], other_sw, link['other_port']]
        new_links = list(links)
        new_links = self.remove_old_link_for_ff(l, new_links)

        link = self.find_group_rule(new_links, sw, link, other_sw, group_links)

        return link


    def find_indirect_group(self, datapath, sw, route, links, group_links,
                             group_id, switches):
        """ Help to fill out group details for switches indirectly connected """
        link = group_links[sw][group_id]
        next_hop_id = switches[route[1]]['dp_id']
        out_port = group_links[sw][next_hop_id]['main']
        group_links[sw][group_id] = {
                    "main": out_port,
                    "other_sw": route[1],
                    "other_port": group_links[sw][next_hop_id]['other_port']
                    }

        link = self.find_link_backup_group(sw, link, links, group_links)

        return link


    def add_group(self, datapath: controller.Datapath, link, group_id):
        """ Helper to build group and add the group to the datapath """
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser
        buckets = self.build_group_buckets(datapath, link)
        msg = ofproto_parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
                                         ofproto.OFPGT_FF, int(group_id),
                                         buckets)
        datapath.send_msg(msg)


    def update_group(self, datapath: controller.Datapath, buckets, group_id):
        """ Helper to update an existing group on the datapath """
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser
        msg = ofproto_parser.OFPGroupMod(datapath, ofproto.OFPGC_MODIFY,
                                         ofproto.OFPGT_FF, int(group_id),
                                         buckets)
        datapath.send_msg(msg)


    def remove_group(self, datapath, group_id):
        """ Helper to remove an existing group from the datapath """
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser
        msg = ofproto_parser.OFPGroupMod(datapath,
                                         command=ofproto.OFPGC_DELETE,
                                         group_id=group_id)
        datapath.send_msg(msg)


    def build_group_buckets(self, datapath: controller.Datapath, link: dict):
        """ build the groups rule to send to the switch """
        ofproto_parser: ofproto_v1_3_parser
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
        return buckets

    def add_direct_mac_flow(self, datapath, host_name, mac, vid, tagged, port,
                            priority=DEFAULT_PRIORITY, cookie=DEFAULT_COOKIE):
        """ Add mac flow for directly connected host """
        match, instructions = self.build_direct_mac_flow_out(datapath, mac, vid,
                                                             tagged, port)
        self.add_flow(datapath, match, instructions, OUT_TABLE, cookie, priority)


    def build_direct_mac_flow_out(self, datapath: controller.Datapath, mac, vid,
                                  tagged, port):
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
                                 tagged, port):
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
        match, instructions = self.build_direct_ipv4_out(datapath, mac, ipv4,
                                                         vid, tagged, port)
        self.add_flow(datapath, match, instructions, OUT_TABLE, cookie, priority)


    def build_direct_ipv4_out(self, datapath: controller.Datapath, mac, ipv4,
                              vid, tagged, port):
        """ Builds match and instructions for the in table for ipv4 of hosts
            that are directly connected"""
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser
        match = None
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

        return match, instructions


    def add_direct_ipv6_flow(self, datapath, host_name, mac, ipv6, vid, tagged,
                             port, priority=DEFAULT_PRIORITY,
                             cookie=DEFAULT_COOKIE):
        """ Add ipv6 arp rule for directly connected host """
        match, instructions = self.build_direct_ipv6_out(datapath, mac, ipv6,
                                                         vid, tagged, port)
        self.add_flow(datapath, match, instructions, OUT_TABLE, cookie, priority)


    def build_direct_ipv6_out(self, datapath: controller.Datapath, mac, ipv6,
                              vid, tagged, port):
        """ Builds the match and instructions for IPv6 flows of hosts that are
            are directly connected """
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser
        match = None
        actions = []
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
        return match, instructions


    def add_indirect_mac_flow(self, datapath, host_name, mac, vid, group_id,
                              priority=DEFAULT_PRIORITY, cookie=DEFAULT_COOKIE):
        """ Add mac rule for indirectly connected hosts """
        match, instructions = self.build_indirect_mac_flow_out(datapath, mac,
                                                          vid, group_id)
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
        match, instructions = self.build_indirect_ipv4_out(datapath, mac, ipv4,
                                                           vid, group_id)
        self.add_flow(datapath, match, instructions, OUT_TABLE, cookie, priority)


    def build_indirect_ipv4_out(self, datapath: controller.Datapath, mac, ipv4,
                                vid, group_id):
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser
        match = None
        instructions = []

        match = ofproto_parser.OFPMatch(vlan_vid=(ofproto.OFPVID_PRESENT | vid),
                                        eth_type=ether_types.ETH_TYPE_ARP,
                                        arp_tpa=self.clean_ip_address(ipv4))

        instructions = [ofproto_parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            [ofproto_parser.OFPActionSetField(eth_dst=mac),
                             ofproto_parser.OFPActionGroup(group_id)])]
        return match, instructions


    def add_indirect_ipv6_flow(self, datapath, host_name, mac, ipv6, vid,
                               group_id, priority=DEFAULT_PRIORITY,
                               cookie=DEFAULT_COOKIE):
        """ Add ipv6 rule for inderectly connected hosts """
        match, instructions = self.build_indirect_ipv6_out(datapath, mac, ipv6,
                                                           vid, group_id)
        self.add_flow(datapath, match, instructions, OUT_TABLE, cookie, priority)


    def build_indirect_ipv6_out(self, datapath: controller.Datapath, mac, ipv6,
                                vid, group_id):
        """ Builds the match and instructions for IPv6 flows of hosts that are
            are directly connected """
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser
        match = None
        instructions = []

        match = ofproto_parser.OFPMatch(vlan_vid=(ofproto.OFPVID_PRESENT | vid),
                                        icmpv6_type=135, ip_proto=58,
                                        eth_type=34525,
                                        ipv6_nd_target=self.clean_ip_address(ipv6))

        instructions = [ofproto_parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            [ofproto_parser.OFPActionSetField(eth_dst=mac),
                             ofproto_parser.OFPActionGroup(group_id)])]

        return match, instructions


    def add_in_flow(self, port, datapath, mac=None, vlan=None, tagged=False,
                    priority=DEFAULT_PRIORITY, cookie=DEFAULT_COOKIE):
        """ Constructs flow for in table """
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = None
        actions = []
        if mac:
            match, actions = self.build_direct_mac_flow_in(datapath, mac, vlan,
                                                           tagged, port)
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


    def remove_flow(self, datapath, match, instructions, table_id):
        """ Helper to remove a particular rule from the datapath """
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser

        flow_mod = ofproto_parser.OFPFlowMod(datapath=datapath,
                                             command=ofproto.OFPFC_DELETE,
                                             table_id=table_id,
                                             match=match,
                                             instructions=instructions)
        datapath.send_msg(flow_mod)


    def update_flow(self, datapath, match, instructions, table_id):
        """ Helper to update a rule on the datapath """
        ofproto: ofproto_v1_3
        ofproto = datapath.ofproto
        ofproto_parser: ofproto_v1_3_parser
        ofproto_parser = datapath.ofproto_parser

        flow_mod = ofproto_parser.OFPFlowMod(datapath=datapath,
                                             command=ofproto.OFPFC_MODIFY,
                                             table_id=table_id,
                                             match=match,
                                             instructions=instructions)
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
        else:
            li = [link_to_remove[2], link_to_remove[3],
                link_to_remove[0], link_to_remove[1]]
            try:
                new_links.remove(li)
            except:
                self.logger.error("Error trying to remove link from the core.")
                self.logger.error(f"Link to remove: {str(link_to_remove)}")
                self.logger.error(f"Link Array: {str(links)}")
        return new_links


    def find_group_rule(self, links, sw, sw_link, target_sw, group_links):
        """ Find the path between 2 switches and create links for them """
        route = self.find_route(links, sw, target_sw)
        if route:
            backup = [v['main'] for k,v in group_links[sw].items() 
                      if route[1] == v['other_sw']]
            sw_link['backup'] = str(backup[0])

        return sw_link


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


    def store_rollbacks(self, config_file: str, rollback_directory: str):
        """ Stores the running config file in the rollback area, and move the 
            previous running config to rollback """
        try:
            file_list = os.listdir(rollback_directory)
            if len(file_list) > 1:
                rollback_files = [f for f in file_list if f.endswith('.rollback')]
                running_files = [f for f in file_list if f.endswith('.running')]

                if len(rollback_files) > 0:
                    rollback_file = rollback_files[0]
                    self.move_rollback_conf_to_backups(
                        f"{rollback_directory}/{rollback_file}")
                if len(running_files) > 0:
                    running_file = running_files[0]
                    self.move_running_conf_to_rollback(
                        f"{rollback_directory}/{running_file}")
            now = datetime.now()
            datefmt = "%Y-%m-%d-%H:%M:%S"
            running_conf_fname = f"{now.strftime(datefmt)}.running"
            shutil.copy(config_file, 
                        f"{rollback_directory}/{running_conf_fname}")
        except Exception as err:
            self.logger.error("Error storing rollback")
            self.logger.error(err)

    def move_rollback_conf_to_backups(self, rollback_file):
        """ Stores the last rollback config to the list of backup files """
        try:
            cleaned_roll_back_name = f"{rollback_file.split('.')[0]}.json"
            shutil.move(rollback_file, cleaned_roll_back_name)
        except Exception as err:
            self.logger.error("Error in storing the backups")
            self.logger.error(f"Rollback filename:{rollback_file}")
            self.logger.error(err)

    def move_running_conf_to_rollback(self, running_file):
        """ Sores the last running config to be the rollback config """
        try:
            new_rollback_name = f"{running_file.split('.')[0]}.rollback"
            shutil.move(running_file, new_rollback_name)
        except Exception as err:
            self.logger.error("Error in moving the running file to be rollback")
            self.logger.error(f"Running conf name:{running_file}")
            self.logger.error(err)


    def copy_failed_config_to_failed_dir(self, config_file: str, 
                                         failed_conf_directory: str):
        """ Copy a failed config to the failed config directory for analysis 
            later. This is primarily to help with scripting issues

        Args:
            config_file (str): Path of failed config file to store in the failed
                               directory
            failed_conf_directory (str): Directory where failed configs are 
                                         to be stored
        """
        try:
            shutil.copy(config_file, f"{failed_conf_directory}/{config_file}")
        except Exception as err:
            self.logger.error("Error storing the failed config in the failed" +
                              f"config directory! (Ironic isn't it?)")
            self.logger.error(f"Failed to copy: {config_file} " + 
                              f"into: {failed_conf_directory}")




    def rollback_files_exist(self, rollback_directory: str) -> bool:
        """ Goes through the rollback directory and see if there are any 
            potential candidates to rollback to

        Args:
            rollback_directory (str): Directory to search rollback files in

        Returns:
            bool: rollback Candidate exists
        """
        if len(os.listdir(rollback_directory)) < 1:
            return False
        file_list = [f for f in os.listdir(rollback_directory) 
                     if f.endswith(".running")
                     or f.endswith(".rollback")
                     or f.endswith(".json")]
        if len(file_list) > 0:
            return True
        return False


    def get_rollback_running_config(self, rollback_directory: str):
        """Finds the previous running config to use for roll back

        Args:
            rollback_directory (str): Directory to look in for rollback config 
            files

        Returns:
            dict: Config file or None if no file is found
        """
        try:
            # if len(os.listdir(rollback_directory)) < 1:
            #     return None
            if not self.rollback_files_exist(rollback_directory):
                return None
            file_list = [f for f in os.listdir(rollback_directory) 
                         if f.endswith(".running")]
            # Look to see if there was a previous working running config
            if len(file_list) > 0:
                last_running_conf = file_list[0]
                return self.open_config_file(
                    f"{rollback_directory}/{last_running_conf}")
            # If not see if there is a previous rollback file
            if len([f for f in os.listdir(rollback_directory) 
                    if f.endswith(".rollback")]) > 0:
                rollback_file = [f for f in os.listdir(rollback_directory) 
                                 if f.endswith(".rollback")][0]
                return self.open_config_file(
                                    f"{rollback_directory}/{rollback_file}")
            # Looks even further back to see if there are any previous files at all
            # Here be dragons
            if len([f for f in os.listdir(rollback_directory) 
                    if f.endswith(".json")]) > 0:
                files = [f for f in os.listdir(rollback_directory) 
                         if f.endswith(".json")]
                sorted_files = sorted(files, reverse=True)
                conf_to_load = sorted_files[0]
                return self.open_config_file(
                            f"{rollback_directory}/{conf_to_load}")
            # Files found but does not meet any criteria for rollback
            return None
        except Exception as err:
            self.logger.error("Error in retrieving the last known " + 
                              "running config")
            self.logger.error(err)
 

    def compare_and_update_groups(self, datapath: controller.Datapath, groups):
        """ Compares pulled rules with generated rules to see if they need to
            be added,updated or removed """
        group_links = self.config['group_links']
        dp_name = self.config['dp_id_to_sw_name'][datapath.id]
        switches = self.config['switches']
        links = self.config['links']
        isolated_switches = Parser(self.logname).find_isolated_switches(group_links)

        if dp_name in isolated_switches:
            for group_id in isolated_switches[dp_name]:
                link = isolated_switches[dp_name][group_id]
                buckets = self.build_group_buckets(datapath, link)
                groups = self.assess_groups(datapath, groups, group_id,
                                            buckets, link)
        else:
            for other_sw, details in switches.items():
                if dp_name == other_sw:
                    continue
                target_dp_id = details['dp_id']
                if target_dp_id in group_links[dp_name]:
                    link = group_links[dp_name][target_dp_id]
                    if 'backup' not in link:
                        link = self.find_link_backup_group(dp_name, link,
                                                        links, group_links)
                    buckets = self.build_group_buckets(datapath, link)
                    groups = self.assess_groups(datapath, groups, target_dp_id,
                                                buckets, link)
                else:
                    route = self.find_route(links, dp_name, other_sw)

                    if route:
                        sw_link = self.find_indirect_group(datapath, dp_name,
                                                    route, links, group_links,
                                                    target_dp_id, switches)
                        buckets = self.build_group_buckets(datapath, sw_link)
                        groups = self.assess_groups(datapath, groups, target_dp_id,
                                                buckets, sw_link)

        if len(groups) > 1:
            for group in groups:
                self.remove_group(datapath, group['group_id'])
        return


    def assess_groups(self, datapath, groups, group_id, buckets, link):
        """ Assess whether a group and bucket combination exists """
        if self.buckets_groups_match(groups, group_id, buckets):
            # Remove group if it's been found
            groups = [g for g in groups if g['group_id'] != group_id]
            return groups
        if self.group_id_exists(groups, group_id):
            # Remove group if it's been found
            groups = [g for g in groups if g['group_id'] != group_id]
            self.update_group(datapath, buckets, group_id)
            return groups
        self.add_group(datapath, link, group_id)
        return groups


    def group_id_exists(self, groups, group_id):
        """ Checks to see if the group_id is present on the switch """
        for group in groups:
            if group_id == group['group_id']:
                return True
        return False


    def buckets_groups_match(self, groups, group_id, buckets):
        """ Checks to ensure that the group on the switch matches the
            expected group """

        for group in groups:
            if group_id == group['group_id'] and buckets == group['buckets']:
                return True
        return False


    def check_if_host_in_flows(self, datapath: controller.Datapath, host, port,
                               flows, group_id=None):
        """ Helper function to see if a host exists on the switch """
        host_name = host['name']
        mac = host['mac']
        vlan_id = host['vlan'] if 'vlan' in host else None
        tagged = host['tagged'] if 'tagged' in host else None
        ipv4 = host['ipv4'] if 'ipv4' in host else None
        ipv6 = host['ipv6'] if 'ipv6' in host else None

        mac_result, flows = self.check_mac_flow_exist(datapath,
                                        mac, vlan_id, tagged, port,
                                        flows, group_id)
        if mac_result == FLOW_NOT_FOUND or mac_result == FLOW_OLD_DELETE:
            if group_id:
                self.add_indirect_mac_flow(datapath, host_name, mac,
                                           vlan_id, group_id)
            else:
                self.add_direct_mac_flow(datapath, host_name, mac,
                                         vlan_id, tagged, port)
                self.add_in_flow(port, datapath, mac, vlan_id, tagged)

        if ipv4:
            v4_result, flows = self.check_ipv4_flow_exist(datapath,
                                                mac, ipv4, vlan_id, tagged,
                                                port, flows, group_id)
            if v4_result == FLOW_NOT_FOUND or v4_result == FLOW_OLD_DELETE:
                if group_id:
                    self.add_indirect_ipv4_flow(datapath, host_name, mac, ipv4,
                                                vlan_id, group_id)
                else:
                    self.add_direct_ipv4_flow(datapath, host_name, mac, ipv4,
                                              vlan_id, tagged, port)
            if v4_result == FLOW_TO_UPDATE:
                if group_id:
                    match, inst = self.build_indirect_ipv4_out(datapath, mac,
                                                        ipv4, vlan_id, group_id)
                else:
                    match, inst = self.build_direct_ipv4_out(datapath, mac,
                                                    ipv4, vlan_id, tagged, port)
                self.update_flow(datapath, match, inst, OUT_TABLE)
        if ipv6:
            v6_result, flows = self.check_ipv6_flow_exist(datapath, mac, ipv6,
                                        vlan_id, tagged, port, flows, group_id)
            if v6_result == FLOW_NOT_FOUND or v6_result == FLOW_OLD_DELETE:
                if group_id:
                    self.add_indirect_ipv6_flow(datapath, host_name, mac, ipv6,
                                                vlan_id, group_id)
                else:
                    self.add_direct_ipv6_flow(datapath, host_name, mac, ipv6,
                                              vlan_id, tagged, port)
            if v6_result == FLOW_TO_UPDATE:
                if group_id:
                    match, inst = self.build_indirect_ipv6_out(datapath, mac,
                                                        ipv6, vlan_id, group_id)
                else:
                    match, inst = self.build_direct_ipv6_out(datapath,
                                            host_name, mac, ipv6, vlan_id, port)
                    self.update_flow(datapath, match, inst, OUT_TABLE)

        return flows


    def check_ipv6_flow_exist(self, datapath, mac, ipv6, vlan_id, tagged,
                                  port, flows, group_id=None):
        """ Checks if the ipv6 address exists in the flow table """
        exists = FLOW_NOT_FOUND

        if not group_id:
            match, inst = self.build_direct_ipv6_out(datapath, mac, ipv6,
                                                     vlan_id, tagged, port)
        else:
            match, inst = self.build_indirect_ipv6_out(datapath, mac, ipv6,
                                                       vlan_id, group_id)

        out_flows = [f for f in flows if f['table_id'] == OUT_TABLE]
        exists, flow = self.check_if_flows_match(out_flows, match, inst)

        if exists != FLOW_NOT_FOUND:
            flows.remove(flow)

        if exists == FLOW_OLD_DELETE:
            self.remove_flow(datapath, flow['match'], flow['instructions'],
                             OUT_TABLE)

        return exists, flows


    def check_ipv4_flow_exist(self, datapath, mac, ipv4, vlan_id, tagged,
                                  port, flows, group_id=None):
        """ Checks if the ipv4 address exists in the flow table """
        exists = FLOW_NOT_FOUND

        if not group_id:
            match, inst = self.build_direct_ipv4_out(datapath, mac, ipv4,
                                                     vlan_id, tagged, port)
        else:
            match, inst = self.build_indirect_ipv4_out(datapath, mac, ipv4,
                                                       vlan_id, group_id)

        out_flows = [f for f in flows if f['table_id'] == OUT_TABLE]

        exists, flow = self.check_if_flows_match(out_flows, match, inst)

        if exists != FLOW_NOT_FOUND:
            flows.remove(flow)
        if exists == FLOW_OLD_DELETE:
            self.remove_flow(datapath, flow['match'], flow['instructions'],
                             OUT_TABLE)

        return exists, flows


    def check_mac_flow_exist(self, datapath, mac, vlan_id, tagged, port,
                                 flows, group_id=None):
        """ Checks to see if the mac address exists in the flow table """
        exists = FLOW_NOT_FOUND
        in_flows = [f for f in flows if ['table_id'] == IN_TABLE]
        out_flows = [f for f in flows if f['table_id'] == OUT_TABLE]
        if not group_id:
            in_match, in_inst = self.build_direct_mac_flow_in(datapath, mac,
                                                              vlan_id, tagged,
                                                              port)
            exists, flow = self.check_if_flows_match(in_flows, in_match, in_inst)
            if exists == FLOW_NOT_FOUND:
                return exists, flows

            flows.remove(flow)
            out_match, out_inst = self.build_direct_mac_flow_out(datapath, mac,
                                                        vlan_id, tagged, port)
            if exists == FLOW_OLD_DELETE:
                self.remove_flow(datapath, flow['match'], flow['instructions'],
                                 IN_TABLE)
                _, out_flow = self.check_if_flows_match(out_flows, out_match,
                                                        out_inst)
                flows.remove(out_flow)
                self.remove_flow(datapath, out_flow['match'],
                                 out_flow['instructions'], OUT_TABLE)
                return exists, flows

            if exists == FLOW_TO_UPDATE:
                self.update_flow(datapath, in_match, in_inst, IN_TABLE)
                _, out_flow = self.check_if_flows_match(out_flows, out_match,
                                                        out_inst)
                flows.remove(out_flow)
                self.update_flow(datapath, out_match, out_inst, OUT_TABLE)
                return exists, flows

        else:
            out_match, out_inst = self.build_indirect_mac_flow_out(datapath, mac,
                                                            vlan_id, group_id)

        exists, flow = self.check_if_flows_match(out_flows, out_match, out_inst)
        if exists != FLOW_NOT_FOUND:
            flows.remove(flow)
        if exists == FLOW_OLD_DELETE:
            self.remove_flow(datapath, flow['match'], flow['instructions'],
                             OUT_TABLE)
        return exists, flows


    def check_if_flows_match(self, flows, match, instructions):
        """ Helper to see if a generated flow matches a pulled one """
        exists = FLOW_NOT_FOUND
        for flow in flows:
            if match in flow['match'] and instructions in flow['instructions']:
                exists = FLOW_EXISTS
                return exists, flow
            # Only check match, since we can't update the match part
            if match in flow['match']:
                exists = FLOW_TO_UPDATE
                return exists, flow
            if instructions in flow['instructions']:
                exists = FLOW_OLD_DELETE
                return exists, flow
        return exists, {}


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