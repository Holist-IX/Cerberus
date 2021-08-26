""" Proactive layer 2 Openflow Controller """

from ast import Return
from itertools import filterfalse
import logging
import json
import os
import sys

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
        self.logger = self.setup_logger()
        self.config = self.get_config_file()

    def get_config_file(self, config_file=DEFAULT_CONFIG):
        """ Reads config file from file and checks it's validity """
        config = self.open_config_file(config_file)
        if not self.check_config(config):
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

    def check_config(self, config):
        """ Checks if the config file is valid """

        err_msg = "Malformed config detected!"
        try:
            if "hosts_matrix" not in config:
                raise ConfigError(f"{err_msg}No 'hosts_matrix' found\n")
            if "switch_matrix" not in config:
                raise ConfigError(f"{err_msg}No 'hosts_matrix' found\n")
        except ConfigError as err:
            self.logger.error(err)
            return False
        if not self.check_hosts_config(config["hosts_matrix"]):
            return False
        if not self.check_switch_config(config["switch_matrix"]):
            return False
        return True

    def check_hosts_config(self, host_matrix):
        """ Parses and validates the hosts matrix """
        err_msg = ("Malformed config detected in the hosts section!\n" +
                   "Please check the config:\n")
        try:
            if not host_matrix:
                raise ConfigError(f"{err_msg} hosts matrix is empty")
            for host in host_matrix:
                if "name" not in host:
                    raise ConfigError(f"{err_msg} Host doesn't have a name")
                if "interfaces" not in host:
                    raise ConfigError(f"{err_msg} Host has no interfaces")
                if not self.check_host_interfaces(err_msg, host):
                    return False
            return True
        except ConfigError as err:
            self.logger.error(err)
            return False
        

    def check_host_interfaces(self, err_msg, host):
        """ Parse and validates the host's interfaces """
        err_msg = err_msg + f"Host: {host['name']} has an error"

        try:
            if not host["interfaces"]:
                raise ConfigError(f"{err_msg} interfaces section is empty")

            for iface in host["interfaces"]:
                if "swport" not in iface:
                    raise ConfigError(f"{err_msg}. It has no switch port\n")
                if "switch" not in iface:
                    raise ConfigError(f"{err_msg}. It does not have an " +
                                      "assigned switch\n")
                if "ipv4" in iface:
                    if not self.check_ipv4_address(err_msg, iface["ipv4"]):
                        return False
                if "ipv6" in iface:
                    if not self.check_ipv6_address(err_msg, iface["ipv6"]):
                        return False
                if "ipv4" not in iface and "ipv6" not in iface:
                    raise ConfigError(f"{err_msg}. It has neither an IPv4" +
                                      " or IPv6 address\n")
                if "mac" not in iface:
                    iface["mac"] = \
                        self.check_for_available_mac(err_msg, iface,
                                                     host["interfaces"])
                if not self.check_mac_address(err_msg, iface["mac"]):
                    return False
                if "vlan" in iface:
                    if not self.check_vlan_validity(err_msg, iface["vlan"]):
                        return False
            return True

        except ConfigError as err:
            self.logger.error(err)
            return False

    def check_ipv4_address(self, err_msg, v4_address):
        """ Checks validity of ipv4 address """
        try:
            if not v4_address:
                raise ConfigError(f"{err_msg} please check that ipv4 sections" +
                                  "have addresses assigned")
            if "." not in v4_address or "/" not in v4_address:
                raise ConfigError(f"{err_msg} in the ipv4 section. " +
                                  f"IPv4 address: {v4_address}")
            return True
        except ConfigError as err:
            self.logger.error(err)
            return False

    def check_ipv6_address(self, err_msg, v6_address):
        """ Checks validity of ipv6 address """
        try:
            if not v6_address:
                raise ConfigError(f"{err_msg} please check that ipv6 sections" +
                                  "have addresses assigned")
            if ":" not in v6_address or "/" not in v6_address:
                raise ConfigError(f"{err_msg} in the ipv6 section. " +
                                  f"IPv6 address: {v6_address}")
            return True
        except ConfigError as err:
            self.logger.error(err)
            return False

    def check_mac_address(self, err_msg, mac_address):
        """ Checks validity of MAC address """
        try:
            if not mac_address:
                raise ConfigError(f"{err_msg} please check that MAC sections" +
                                  "have addresses assigned")
            if ":" not in mac_address:
                raise ConfigError(f"{err_msg} in the MAC section. Currently " +
                                  "only : seperated addresses are supported\n" +
                                  f"MAC Address: {mac_address}\n")
            return True
        except ConfigError as err:
            self.logger.error(err)
            return False

    def check_for_available_mac(self, err_msg, iface, host_interfaces):
        """ Checks port if another mac address is assigned to the port """
        mac = ""
        try:
            for other_iface in host_interfaces:
                if iface is other_iface:
                    continue

                if iface["switch"] == other_iface["switch"] and \
                        iface["swport"] == other_iface["swport"] and \
                        "mac" in other_iface:

                    mac = other_iface["mac"]

            if not mac:
                raise ConfigError(f"{err_msg} in the mac section. " +
                                  "No mac address was provided")
        except ConfigError as err:
            self.logger.error(err)
            return None

        return mac

    def check_vlan_validity(self, err_msg, vlan):
        """ Checks that the assigned vlan is a valid value """
        try:
            vid = int(vlan)
            if vid < 0 or vid > 4095:
                raise ConfigError(f"{err_msg}. Invalid vlan id(vid) detected" +
                                  "Vid should be between 1 and 4095. " +
                                  f"Vid: {vid} detected\n")
            return True
        except (ConfigError, ValueError) as err:
            self.logger.error(err)
            return False

    def check_switch_config(self, sw_matrix):
        """ Parses and validates the switch matrix """
        err_msg = ("Malformed config detected in the switch section!\n" +
                   "Please check the config:\n")
        try:
            if not sw_matrix:
                raise ConfigError(f"{err_msg}Switch matrix is empty")
            if "links" not in sw_matrix:
                raise ConfigError(f"{err_msg}No links section found")
            for link in sw_matrix["links"]:
                self.check_valid_link(link, err_msg)
            self.check_dp_ids(sw_matrix, err_msg)
            if "p4" in sw_matrix:
                self.p4_switches = sw_matrix["p4"]
            if "unmanaged_switches" in sw_matrix:
                self.unmanaged_switches = sw_matrix["unmanaged_switches"]
            self.link_matrix = sw_matrix["links"]
            return True

        except ConfigError as err:
            self.logger.error(err)
            return False
        except ValueError as err:
            self.logger.error(f"{err_msg} Please check value of port numbers")
            self.logger.error(err)
            return False

    def check_dp_ids(self, sw_matrix, err_msg):
        """ Checks if the dp id section is valid in the  """
        if "dp_ids" not in sw_matrix:
            raise ConfigError(f"{err_msg}No dp_id section found!\n" +
                              "Please specify dp_ids to communicate with")

        else:
            for _, dp_id in sw_matrix["dp_ids"].items():
                if not hex(dp_id):
                    raise ConfigError(f"{err_msg}Please ensure that" +
                                      " dp_ids are valid numbers")
            self.switch_dps = sw_matrix["dp_ids"]

    def check_valid_link(self, link, err_msg):
        """ Parses link and checks if it is valid """
        if len(link) != 4:
            raise ConfigError(f"{err_msg}Invalid link found." +
                              "Expected link format:\n" +
                              "[switch1,switch1_port,switch2,switch2_port]\n" +
                              "\nLink found: {link}")
        port_a = int(link[1])
        port_b = int(link[3])

        if port_a < 0 or port_a > 255 or port_b < 0 or port_b > 255:
            raise ConfigError("Invalid port number detected. Ensure" +
                              "that port numbers are between 0 and 255" +
                              f"sw1_port: {port_a}\t sw2_port:{port_b}")

    def setup_logger(self, loglevel=logging.INFO,
                     logfile=DEFAULT_LOG_FILE, quiet=False):
        """ Setup and return the logger """
        logname = 'cerberus'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(name)s %(levelname)s %(message)s',
            datefmt='%b %d %H:%M:%S',
            filename=logfile,
            filemode='a+')
        if quiet:
            console = logging.StreamHandler(sys.stdout)
            console.setLevel(loglevel)
            console.setFormatter(logging.Formatter('%(message)s'))
            logging.getLogger().addHandler(console)
        logger = logging.getLogger(logname)

        return logger
