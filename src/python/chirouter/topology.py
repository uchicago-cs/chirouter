# Network topologies
#
# A topology (loaded from one of the JSON files in the topologies/ directory)
# specifies the hosts, switches, and chirouter-managed routers in a simulated
# network (including the interfaces and routing tables of the routers),
# and how they are linked together.

from __future__ import annotations

import binascii
import ipaddress
import json
from typing import IO, Any, Self


def check_fields(d: dict[str, Any], fields: tuple[str, ...],
                 what: str) -> None:
    '''
    Checks that a dictionary (from a topology file) has some fields.

    Inputs:
      d (dict): the dictionary.
      fields (tuple of str): the names of the fields.
      what (str): what the dictionary represents (used in error messages).

    Returns: nothing. Raises a ValueError if a field is missing.
    '''
    for f in fields:
        if f not in d:
            raise ValueError("{} is missing '{}' field".format(what, f))


class Interface:
    '''
    A network interface (in a host or a router)
    '''

    def __init__(self, name: str, iface: ipaddress.IPv4Interface,
                 hwaddr: str | None = None,
                 gateway: ipaddress.IPv4Address | None = None) -> None:
        '''
        Constructor

        Inputs:
          name (str): name of the interface (e.g., "eth0").
          iface (IPv4Interface): IP address and netmask of the interface.
          hwaddr (str | None): MAC address of the interface (e.g.,
            "02:00:00:00:00:01"), if known.
          gateway (IPv4Address | None): default gateway, for host interfaces.
        '''
        self.name = name
        self._iface = iface
        self.hwaddr = hwaddr
        self.gateway = gateway

    @property
    def ip_with_prefixlen(self) -> str:
        '''
        The IP address of the interface, with the length of the network
        prefix (e.g., "10.0.0.1/8")
        '''
        return self._iface.with_prefixlen

    @property
    def ip_packed(self) -> bytes:
        '''
        The IP address of the interface, as four bytes
        '''
        return self._iface.packed

    @property
    def hwaddr_packed(self) -> bytes:
        '''
        The MAC address of the interface, as six bytes (the MAC address
        must have been set)
        '''
        assert self.hwaddr is not None
        return binascii.unhexlify(self.hwaddr.replace(":", ""))

    def __repr__(self) -> str:
        '''
        Returns:
          (str) a representation of the interface (for debugging).
        '''
        return "<Interface {} {}>".format(self.name, self.ip_with_prefixlen)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Self:
        '''
        Creates an interface from its description in a topology file.

        Inputs:
          d (dict): the interface's entry in the topology file.

        Returns:
          (Interface) the interface. Raises a ValueError if a field
          is missing.
        '''
        check_fields(d, ("name", "ip", "mask"), "Interface")

        iface = ipaddress.IPv4Interface("{}/{}".format(d["ip"], d["mask"]))

        hwaddr = d.get("hwaddr")

        gateway: ipaddress.IPv4Address | None
        if "gateway" in d:
            gateway = ipaddress.IPv4Address(d["gateway"])
        else:
            gateway = None

        return cls(d["name"], iface, hwaddr, gateway)


class RTableEntry:
    '''
    An entry in a router's routing table
    '''

    def __init__(self, network: ipaddress.IPv4Interface,
                 gateway_addr: ipaddress.IPv4Address,
                 metric: int, iface: str) -> None:
        '''
        Constructor

        Inputs:
          network (IPv4Interface): destination network (and netmask).
          gateway_addr (IPv4Address): gateway (0.0.0.0 if there is no gateway).
          metric (int): metric of this entry.
          iface (str): name of the router interface for this entry.
        '''
        self.network = network
        self.gateway_addr = gateway_addr
        self.is_gateway = int(gateway_addr) != 0
        self.metric = metric
        self.iface = iface

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Self:
        '''
        Creates a routing table entry from its description in a topology file.

        Inputs:
          d (dict): the entry in the topology file.

        Returns:
          (RTableEntry) the routing table entry. Raises a ValueError if a
          field is missing.
        '''
        check_fields(d, ("destination", "gateway", "mask", "metric", "iface"),
                     "Routing Table Entry")

        network = ipaddress.IPv4Interface(
            "{}/{}".format(d["destination"], d["mask"]))
        gateway_addr = ipaddress.IPv4Address(d["gateway"])

        return cls(network, gateway_addr, d["metric"], d["iface"])


class Switch:
    '''
    A switch (which will be simulated with a Linux bridge)
    '''

    def __init__(self, id: int) -> None:
        '''
        Constructor

        Inputs:
          id (int): ID of the switch.
        '''
        self.id = id
        self.interfaces: dict[str, Interface] = {}

    @property
    def name(self) -> str:
        '''
        The name of the switch in Mininet
        '''
        return "s{}".format(self.id)

    def __repr__(self) -> str:
        '''
        Returns:
          (str) a representation of the switch (for debugging).
        '''
        return "<Switch {}>".format(self.name)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Self:
        '''
        Creates a switch from its description in a topology file.

        Inputs:
          d (dict): the switch's entry in the topology file.

        Returns:
          (Switch) the switch. Raises a ValueError if a field is missing.
        '''
        check_fields(d, ("id",), "Switch")

        return cls(d["id"])


class Router(Switch):
    '''
    A chirouter-managed router
    '''

    def __init__(self, id: int) -> None:
        '''
        Constructor

        Inputs:
          id (int): ID of the router.
        '''
        super().__init__(id)

        self.rtable: list[RTableEntry] = []

    @property
    def name(self) -> str:
        '''
        The name of the router in Mininet (and in chirouter)
        '''
        return "r{}".format(self.id)

    @property
    def num_interfaces(self) -> int:
        '''
        The number of interfaces in the router
        '''
        return len(self.interfaces)

    @property
    def len_rtable(self) -> int:
        '''
        The number of entries in the router's routing table
        '''
        return len(self.rtable)

    def add_interface(self, iface: Interface) -> None:
        '''
        Adds an interface to the router.

        Inputs:
          iface (Interface): the interface.

        Returns: nothing.
        '''
        self.interfaces[iface.name] = iface

    def add_rtable_entry(self, rtable_entry: RTableEntry) -> None:
        '''
        Adds an entry to the router's routing table.

        Inputs:
          rtable_entry (RTableEntry): the entry. Its interface must
            have already been added to the router.

        Returns: nothing. Raises a ValueError if the entry's interface
        is not one of the router's interfaces.
        '''
        if rtable_entry.iface not in self.interfaces:
            raise ValueError("Incorrect interface in routing table entry: {}"
                             .format(rtable_entry.iface))

        self.rtable.append(rtable_entry)

    def __repr__(self) -> str:
        '''
        Returns:
          (str) a representation of the router (for debugging).
        '''
        return "<Router {}>".format(self.name)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Self:
        '''
        Creates a router from its description in a topology file.

        Inputs:
          d (dict): the router's entry in the topology file.

        Returns:
          (Router) the router. Raises a ValueError if the description
          is not correct.
        '''
        check_fields(d, ("id", "interfaces", "rtable"), "Router")

        router = cls(d["id"])

        for iface in d["interfaces"]:
            router.add_interface(Interface.from_dict(iface))

        for rtable_entry in d["rtable"]:
            router.add_rtable_entry(RTableEntry.from_dict(rtable_entry))

        return router


class Host:
    '''
    A host
    '''

    def __init__(self, id: int, hostname: str) -> None:
        '''
        Constructor

        Inputs:
          id (int): ID of the host.
          hostname (str): name of the host.
        '''
        self.id = id
        self.hostname = hostname
        self.interfaces: dict[str, Interface] = {}

        # Attributes of the host (e.g., "httpd" if the host runs a web server)
        self.attrs: set[str] = set()

    @property
    def name(self) -> str:
        '''
        The name of the host in Mininet
        '''
        return self.hostname

    def add_interface(self, iface: Interface) -> None:
        '''
        Adds an interface to the host.

        Inputs:
          iface (Interface): the interface.

        Returns: nothing.
        '''
        self.interfaces[iface.name] = iface

    def __repr__(self) -> str:
        '''
        Returns:
          (str) a representation of the host (for debugging).
        '''
        return "<Host {}>".format(self.name)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Self:
        '''
        Creates a host from its description in a topology file.

        Inputs:
          d (dict): the host's entry in the topology file.

        Returns:
          (Host) the host. Raises a ValueError if a field is missing.
        '''
        check_fields(d, ("id", "hostname", "interfaces"), "Host")

        host = cls(d["id"], d["hostname"])

        for iface in d["interfaces"]:
            host.add_interface(Interface.from_dict(iface))

        for a in d.get("attrs", []):
            host.attrs.add(a)

        return host


# A node in the topology
Node = Switch | Router | Host

# A link between two nodes: (node, interface name, node, interface name).
# The interface names are None for switch ports.
Link = tuple[Node, str | None, Node, str | None]


class Topology:
    '''
    A network topology
    '''

    def __init__(self) -> None:
        '''
        Constructor (creates an empty topology)
        '''
        self.switches: list[Switch] = []
        self.routers: list[Router] = []
        self.hosts: list[Host] = []
        self.links: list[Link] = []

        # All the nodes, indexed by ID
        self.nodes: dict[int, Node] = {}

    @property
    def num_routers(self) -> int:
        '''
        The number of chirouter-managed routers in the topology
        '''
        return len(self.routers)

    def add_switch(self, s: Switch) -> None:
        '''
        Adds a switch to the topology.

        Inputs:
          s (Switch): the switch.

        Returns: nothing.
        '''
        self.switches.append(s)
        self.nodes[s.id] = s

    def add_router(self, r: Router) -> None:
        '''
        Adds a router to the topology.

        Inputs:
          r (Router): the router.

        Returns: nothing.
        '''
        self.routers.append(r)
        self.nodes[r.id] = r

    def add_host(self, h: Host) -> None:
        '''
        Adds a host to the topology.

        Inputs:
          h (Host): the host.

        Returns: nothing.
        '''
        self.hosts.append(h)
        self.nodes[h.id] = h

    def add_link(self, src: Node, dst: Node, src_iface: str | None = None,
                 dst_iface: str | None = None) -> None:
        '''
        Adds a link between two nodes to the topology.

        Inputs:
          src, dst (Node): the nodes.
          src_iface, dst_iface (str | None): the names of the interfaces
            in each node (or None for switches).

        Returns: nothing. Raises a ValueError if a node doesn't have the
        specified interface.
        '''
        for node, iface in ((src, src_iface), (dst, dst_iface)):
            if iface and iface not in node.interfaces:
                raise ValueError("Cannot add link. Node {} has no such "
                                 "interface: {}".format(node, iface))

        self.links.append((src, src_iface, dst, dst_iface))

    @classmethod
    def from_json(cls, json_file: IO[str]) -> Self:
        '''
        Loads a topology from a JSON file.

        Inputs:
          json_file (file): the topology file.

        Returns:
          (Topology) the topology. Raises a ValueError if the topology
          file is not correct.
        '''
        t = json.load(json_file)

        check_fields(t, ("switches", "hosts", "links"), "Topology")

        topo = cls()

        for s in t["switches"]:
            check_fields(s, ("type",), "Switch")
            if s["type"] == "switch":
                topo.add_switch(Switch.from_dict(s))
            elif s["type"] == "router":
                topo.add_router(Router.from_dict(s))
            else:
                raise ValueError("Unknown switch type: '{}'".format(s["type"]))

        for h in t["hosts"]:
            topo.add_host(Host.from_dict(h))

        for link in t["links"]:
            src = topo.nodes[link["from"]["id"]]
            dst = topo.nodes[link["to"]["id"]]

            src_iface = link["from"].get("interface")
            dst_iface = link["to"].get("interface")

            topo.add_link(src, dst, src_iface, dst_iface)

        return topo

    def to_mininet_topology(self) -> Any:
        '''
        Creates a Mininet topology for this topology. Hosts are Mininet
        hosts, switches are BridgeSwitches (see switch.py), and routers are
        RouterNodes (see relay.py).

        Returns:
          (mininet.topo.Topo) the Mininet topology.
        '''
        import mininet.topo
        from chirouter.relay import RouterNode
        from chirouter.switch import BridgeSwitch

        topo = mininet.topo.Topo()

        for h in self.hosts:
            topo.addHost(h.hostname)

        for s in self.switches:
            topo.addSwitch(s.name, cls=BridgeSwitch)

        for r in self.routers:
            topo.addSwitch(r.name, cls=RouterNode)

        for src, src_iface, dst, dst_iface in self.links:
            intf_name1: str | None = None
            intf_name2: str | None = None

            if src_iface is not None:
                intf_name1 = src.name + "-" + src_iface
            if dst_iface is not None:
                intf_name2 = dst.name + "-" + dst_iface

            topo.addLink(src.name, dst.name,
                         intfName1=intf_name1, intfName2=intf_name2)

        return topo
