""" Config parser for Cerberus """

import logging

from cerberus.exceptions import *

def check_config(config, logname):
    """ Checks if the config file is valid """
    logger = get_logger(logname)
    err_msg = "Malformed config detected!"
    try:
        if "hosts_matrix" not in config:
            raise ConfigError(f"{err_msg}No 'hosts_matrix' found\n")
        if "switch_matrix" not in config:
            raise ConfigError(f"{err_msg}No 'hosts_matrix' found\n")
        if not check_hosts_config(config["hosts_matrix"], logname):
            return False
        if not check_switch_config(config["switch_matrix"], logname):
            return False
    except ConfigError as err:
        logger.error(err)
        return False
    return True

def check_hosts_config(host_matrix, logname):
    """ Parses and validates the hosts matrix """
    logger = get_logger(logname)
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
            if not check_host_interfaces(err_msg, host, logname):
                return False
        return True
    except ConfigError as err:
        logger.error(err)
        return False
    

def check_host_interfaces(err_msg, host, logname):
    """ Parse and validates the host's interfaces """
    logger = get_logger(logname)
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
                if not check_ipv4_address(err_msg, iface["ipv4"], logname):
                    return False
            if "ipv6" in iface:
                if not check_ipv6_address(err_msg, iface["ipv6"], logname):
                    return False
            if "ipv4" not in iface and "ipv6" not in iface:
                raise ConfigError(f"{err_msg}. It has neither an IPv4" +
                                    " or IPv6 address\n")
            if "mac" not in iface:
                iface["mac"] = \
                    check_for_available_mac(err_msg, iface, host["interfaces"], 
                                            logname)
            if not check_mac_address(err_msg, iface["mac"], logname):
                return False
            if "vlan" in iface:
                if not check_vlan_validity(err_msg, iface["vlan"], logname):
                    return False
        return True

    except ConfigError as err:
        logger.error(err)
        return False

def check_ipv4_address(err_msg, v4_address, logname):
    """ Checks validity of ipv4 address """
    logger = get_logger(logname)
    try:
        if not v4_address:
            raise ConfigError(f"{err_msg} please check that ipv4 sections" +
                                "have addresses assigned")
        if "." not in v4_address or "/" not in v4_address:
            raise ConfigError(f"{err_msg} in the ipv4 section. " +
                              f"IPv4 address: {v4_address}")
        return True
    except ConfigError as err:
        logger.error(err)
        return False

def check_ipv6_address(err_msg, v6_address, logname):
    """ Checks validity of ipv6 address """
    logger = get_logger(logname)
    try:
        if not v6_address:
            raise ConfigError(f"{err_msg} please check that ipv6 sections" +
                                "have addresses assigned")
        if ":" not in v6_address or "/" not in v6_address:
            raise ConfigError(f"{err_msg} in the ipv6 section. " +
                                f"IPv6 address: {v6_address}")
        return True
    except ConfigError as err:
        logger.error(err)
        return False

def check_mac_address(err_msg, mac_address, logname):
    """ Checks validity of MAC address """
    logger = get_logger(logname)
    try:
        if not mac_address:
            raise ConfigError(f"{err_msg} please check that MAC sections " +
                                "have addresses assigned")
        if ":" not in mac_address:
            raise ConfigError(f"{err_msg} in the MAC section. Currently " +
                                "only : seperated addresses are supported\n" +
                                f"MAC Address: {mac_address}\n")
        return True
    except ConfigError as err:
        logger.error(err)
        return False

def check_for_available_mac(err_msg, iface, host_interfaces, logname):
    """ Checks port if another mac address is assigned to the port """
    logger = get_logger(logname)
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
        logger.error(err)
        return None

    return mac

def check_vlan_validity(err_msg, vlan, logname):
    """ Checks that the assigned vlan is a valid value """
    logger = get_logger(logname)
    try:
        vid = int(vlan)
        if vid < 0 or vid > 4095:
            raise ConfigError(f"{err_msg}. Invalid vlan id(vid) detected. " +
                                "Vid should be between 1 and 4095. " +
                                f"Vid: {vid} detected\n")
        return True
    except (ConfigError, ValueError) as err:
        logger.error(err)
        return False

def check_switch_config(sw_matrix, logname):
    """ Parses and validates the switch matrix """
    logger = get_logger(logname)
    err_msg = ("Malformed config detected in the switch section!\n" +
                "Please check the config:\n")
    try:
        if not sw_matrix:
            raise ConfigError(f"{err_msg}Switch matrix is empty")
        if "links" not in sw_matrix:
            raise ConfigError(f"{err_msg}No links section found")
        for link in sw_matrix["links"]:
            check_valid_link(link, err_msg)
        if not check_dp_ids(sw_matrix, err_msg, logname):
            return False
        return True

    except ConfigError as err:
        logger.error(err)
        return False
    except ValueError as err:
        logger.error(f"{err_msg} Please check value of port numbers")
        logger.error(err)
        return False

def check_dp_ids(sw_matrix, err_msg, logname):
    """ Checks if the dp id section is valid in the  """
    logger = get_logger(logname)
    if "dp_ids" not in sw_matrix:
        raise ConfigError(f"{err_msg}No dp_id section found!\n" +
                          "Please specify dp_ids to communicate with")

    else:
        for _, dp_id in sw_matrix["dp_ids"].items():
            if not hex(dp_id):
                raise ConfigError(f"{err_msg}Please ensure that dp_ids are" + 
                                  f" valid numbers.\n dp_id found: {dp_id}")

def check_valid_link(link, err_msg):
    """ Parses link and checks if it is valid """
    print("We're in the check link section")
    if len(link) != 4:
        raise ConfigError(f"{err_msg}Invalid link found. " +
                            "Expected link format:\n" +
                            "[switch1,switch1_port,switch2,switch2_port]\n" +
                            f"Link found: {link}")
    port_a = int(link[1])
    port_b = int(link[3])
    if port_a < 0 or port_a > 255 or port_b < 0 or port_b > 255:
        raise ConfigError("Invalid port number detected. Ensure that port " + 
                          "numbers are between 0 and 255\n" +
                          f"sw1_port: {port_a}\t sw2_port:{port_b}")

def get_logger(logname):
    """ Retrieve logger """
    return logging.getLogger(logname)