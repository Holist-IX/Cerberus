# Cerberus

Cerberus is an OpenFlow controller for OpenFlow 1.3 switches, focusing on
layer-2 switching. Cerberus takes a proactive approach to network configuration
and only allows connections to hosts that are already configured. By taking a
proactive approach to network configuration, Cerberus takes multicast traffic
and translates it to unicast. This eliminates MAC leanring happening on the
switches themselves. Cerberus is build on top of the
[Ryu OpenFlow Controller](https://ryu.readthedocs.io/en/latest/index.html).

The primary design principles oof Cerberus is to reduce as much complexity
within a network, and to have as little impact as possible on a running network.
This means that a switch is largely configured as a "set and forget". Cerberus
will periodically check in if the switch state matches the expected state, but
there is no network learning happening from the switches.

## Features

* OpenFlow 1.3 support
* Translate Multicast to Unicast traffic
* Elimates unwanted traffic within network
* VLAN, both tagged and untagged ports
* IPv4 and IPv6
* Redundancy setup for switches with multiple paths
* Rollback to previous configurations
* REST API support

## Installation

Cerberus can be installed as follows:

``` bash
% pip install cerberus-controller
```

You can also install Cerberus from the source code if you prefer via:

```
% git clone https://github/Holist-IX/cerberus/
% cd cerberus; pip install .
```


## Configuration

The default configuration is located at `/etc/cerberus/topology.json`, with
older configs stored at `/etc/cerberus/rollback/` and failed configs will
be stored at `/etc/cerberus/failed/`.

Below is a sample of the topology config:

``` json

{
    "switch_matrix": {
        // The datapath ID's of the switches
        "dp_ids": {
            "s1": 1,
            "s2": 2
        },
        // Links between switches. Should follow source_switch, source_port, destination_switch, destination_port
        "links": [
            ["s1", "24", "s2", "24"]
        ],
    },
    "hosts_matrix": [{
        "name": "MemberA",
        "interfaces": [{
            "switch": "s1",
            "swport": 1,
            "mac": "00:00:00:00:00:01",
            "ipv4": "10.0.0.1/24",
            "ipv6": "2001:db8:32::1/64",
            "vlan": 1234,
            "tagged": false
        }]
    }, {
        "name": "MemberB",
        "interfaces": [{
            "switch": "s1",
            "swport": 2,
            "mac": "00:00:00:00:00:02",
            "ipv4": "10.0.0.2/24",
            "ipv6": "2001:db8:32::2/64",
            "vlan": 1234,
            "tagged": false
        }]
    }]
}
```
## Support

You can contact us via twiiter [@IxHolist](https://twitter.com/IxHolist).
If you encounter any bugs please open an issue. For more information go to our
[site](https://holistix.iijlab.net/)