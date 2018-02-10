import json
import ipaddress
import struct
import binascii

import mininet.topo

class Interface(object):

    def __init__(self, name, iface, hwaddr=None, gateway=None):
        self.name = name
        self._iface = iface
        self.hwaddr = hwaddr
        self.gateway = gateway

    @property
    def ip_with_prefixlen(self):
        return self._iface.with_prefixlen

    @property
    def ip_packed(self):
        return self._iface.packed

    @property
    def hwaddr_packed(self):
        return binascii.unhexlify(self.hwaddr.replace(":",""))

    def __repr__(self):
        return "<Interface {} {}>".format(self.name, self.ip_with_prefixlen)

    @classmethod
    def from_dict(cls, d):
        for f in ("name", "ip", "mask"):
            if f not in d:
                raise ValueError("Interface is missing '{}' field".format(f))

        iface = ipaddress.ip_interface(u"{}/{}".format(d["ip"], d["mask"]))

        hwaddr = d.get("hwaddr")

        if "gateway" in d:
            gateway = ipaddress.ip_address(d["gateway"])
        else:
            gateway = None

        return cls(d["name"], iface, hwaddr, gateway)

class RTableEntry(object):

    def __init__(self, network, gateway_addr, metric, iface):
        self.network = network
        self.gateway_addr = gateway_addr

        if struct.unpack_from("!I", gateway_addr.packed)[0] != 0:
            self.is_gateway = True
        else:
            self.is_gateway = False

        self.metric = metric
        self.iface = iface

    @classmethod
    def from_dict(cls, d):
        for f in ("destination", "gateway", "mask", "metric", "iface"):
            if f not in d:
                raise ValueError("Routing Table Entry is missing '{}' field".format(f))

        network = ipaddress.ip_interface(u"{}/{}".format(d["destination"], d["mask"]))
        gateway_addr = ipaddress.ip_address(d["gateway"])

        return cls(network, gateway_addr, d["metric"], d["iface"])


class Switch(object):

    def __init__(self, id):
        self.id = id
        self.interfaces = {}

    @property
    def name(self):
        return "s{}".format(self.id)

    def __repr__(self):
        return "<Switch {}>".format(self.name)

    @classmethod
    def from_dict(cls, d):
        if "id" not in d:
            raise ValueError("Switch is missing 'id' field")

        return cls(d["id"])


class Router(Switch):

    def __init__(self, id):
        super(Router, self).__init__(id)

        self.rtable = []

    @property
    def name(self):
        return "r{}".format(self.id)

    @property
    def num_interfaces(self):
        return len(self.interfaces)

    @property
    def len_rtable(self):
        return len(self.rtable)

    def add_interface(self, iface):
        self.interfaces[iface.name] = iface

    def add_rtable_entry(self, rtable_entry):
        if rtable_entry.iface not in self.interfaces:
            raise ValueError("Incorrect interface in routing table entry: {}".format(rtable_entry.iface))

        self.rtable.append(rtable_entry)

    def __repr__(self):
        return "<Router {}>".format(self.name)

    @classmethod
    def from_dict(cls, d):
        for f in ("id", "interfaces", "rtable"):
            if f not in d:
                raise ValueError("Router is missing '{}' field".format(f))

        router = cls(d["id"])

        for iface in d["interfaces"]:
            router.add_interface(Interface.from_dict(iface))

        for rtable_entry in d["rtable"]:
            router.add_rtable_entry(RTableEntry.from_dict(rtable_entry))

        return router

class Host(object):

    def __init__(self, id, hostname):
        self.id = id
        self.hostname = hostname
        self.interfaces = {}
        self.attrs = set()

    @property
    def name(self):
        return self.hostname


    def add_interface(self, iface):
        self.interfaces[iface.name] = iface

    def __repr__(self):
        return "<Host {}>".format(self.name)

    @classmethod
    def from_dict(cls, d):
        for f in ("id", "hostname", "interfaces"):
            if f not in d:
                raise ValueError("Host is missing '{}' field".format(f))

        host = cls(d["id"], d["hostname"])

        for iface in d["interfaces"]:
            host.add_interface(Interface.from_dict(iface))

        if "attrs" in d:
            for a in d["attrs"]:
                host.attrs.add(a)

        return host

class Topology(object):
    
    def __init__(self):
        self.switches = []
        self.routers = []
        self.hosts = []
        self.links = []

        self.nodes = {}

    @property
    def num_routers(self):
        return len(self.routers)

    def add_switch(self, s):
        self.switches.append(s)
        self.nodes[s.id] = s

    def add_router(self, r):
        self.routers.append(r)
        self.nodes[r.id] = r

    def add_host(self, h):
        self.hosts.append(h)
        self.nodes[h.id] = h

    def add_link(self, src, dst, src_iface = None, dst_iface = None):
        if src_iface and src_iface not in src.interfaces:
            raise ValueError("Cannot add link. Node {} has no such interface: {}".format(src, src_iface))

        if dst_iface and dst_iface not in dst.interfaces:
            raise ValueError("Cannot add link. Node {} has no such interface: {}".format(dst, dst_iface))

        self.links.append( (src, src_iface, dst, dst_iface) )

    @classmethod
    def from_json(cls, json_file):
        t = json.load(json_file)

        for f in ("switches", "hosts", "links"):
            if f not in t:
                raise ValueError("Topology field is missing '{}' field".format(f))

        topo = cls()

        switches = []
        routers = []
        for s in t["switches"]:
            if "type" not in s:
                raise ValueError("Switch is missing 'type' field")
            if s["type"] == "switch":
                topo.add_switch(Switch.from_dict(s))
            elif s["type"] == "router":
                topo.add_router(Router.from_dict(s))
            else:
                raise ValueError("Unknown switch type: '{}'".format(s["type"]))

        hosts = []
        for h in t["hosts"]:
            topo.add_host(Host.from_dict(h))

        for l in t["links"]:
            src = topo.nodes[l["from"]["id"]]
            dst = topo.nodes[l["to"]["id"]]

            src_iface = l["from"].get("interface")
            dst_iface = l["to"].get("interface")

            topo.add_link(src, dst, src_iface, dst_iface)

        return topo


    def to_mininet_topology(self):
        topo = mininet.topo.Topo()

        for h in self.hosts:
            mn_host = topo.addHost(h.hostname)

        for s in self.switches + self.routers:
            mn_switch = topo.addSwitch(s.name)

        for src, src_iface, dst, dst_iface in self.links:
            if src_iface is not None:
                intfName1 = src.name + "-" + src_iface
            else:
                intfName1 = None
                
            if dst_iface is not None:
                intfName2 = dst.name + "-" + dst_iface
            else:
                intfName2 = None                
                
            topo.addLink(src.name, dst.name, intfName1=intfName1, intfName2=intfName2)

        return topo