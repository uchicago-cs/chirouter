# Client for the chirouter protocol.
#
# chirouter is a server that implements the routers in a simulated network.
# This module implements the client side of the protocol used to send
# chirouter the configuration of the routers, and to exchange Ethernet frames
# with it. The protocol is described in src/c/server.h.

from __future__ import annotations

import errno
import socket
import struct
from collections.abc import Iterator

from chirouter.topology import Interface, Router, Topology

# Length of the header of a message (type, subtype, and payload length)
MSG_HDR_LEN = 4

# Number of bytes to read from the socket at a time
RECV_SIZE = 4096


class ChirouterMessage:
    '''
    Base class for all the messages in the chirouter protocol.
    '''

    MSG_TYPE_HELLO = 1
    MSG_TYPE_ROUTERS = 2
    MSG_TYPE_ROUTER = 3
    MSG_TYPE_INTERFACE = 4
    MSG_TYPE_RTABLE_ENTRY = 5
    MSG_TYPE_END_CONFIG = 6
    MSG_TYPE_ETHERNET_FRAME = 7

    # These must match the values in src/c/server.h
    SUBTYPE_NONE = 0
    SUBTYPE_FROM_ROUTER = 1
    SUBTYPE_TO_ROUTER = 2

    def __init__(self, msg_type: int, subtype: int) -> None:
        '''
        Constructor

        Inputs:
          msg_type (int): message type (one of the MSG_TYPE_* constants)
          subtype (int): message subtype (one of the SUBTYPE_* constants)
        '''
        self.type = msg_type
        self.subtype = subtype

    def pack(self) -> bytes:
        '''
        Converts the message to its binary representation. Must be
        implemented by each type of message.

        Returns:
          (bytes) the message, including its header.
        '''
        raise NotImplementedError

    @staticmethod
    def from_buffer(buf: bytes) -> ChirouterMessage | None:
        '''
        Parses a message. Only the messages that can be sent by chirouter
        (HELLO and ETHERNET FRAME) are supported.

        Inputs:
          buf (bytes): a complete message, including its header.

        Returns:
          (ChirouterMessage | None) the message, or None if it is not
          a message that can be sent by chirouter.
        '''
        msg_type, msg_subtype, _ = struct.unpack("!BBH", buf[:MSG_HDR_LEN])

        if msg_type == ChirouterMessage.MSG_TYPE_HELLO:
            if msg_subtype == ChirouterMessage.SUBTYPE_TO_ROUTER:
                return ChirouterMessageHello(from_router=False)
            elif msg_subtype == ChirouterMessage.SUBTYPE_FROM_ROUTER:
                return ChirouterMessageHello(from_router=True)
        elif msg_type == ChirouterMessage.MSG_TYPE_ETHERNET_FRAME:
            return ChirouterMessageEthernetFrame.from_buffer(buf)

        return None

    def _pack(self, payload: bytes | None = None) -> bytes:
        '''
        Converts the message to its binary representation, given
        its payload (used by the implementations of pack())

        Inputs:
          payload (bytes | None): the payload of the message (or None,
            if the message has no payload).

        Returns:
          (bytes) the message, including its header.
        '''
        if payload is None:
            return struct.pack("!BBH", self.type, self.subtype, 0)
        else:
            header = struct.pack("!BBH", self.type, self.subtype, len(payload))
            return header + payload


class ChirouterMessageHello(ChirouterMessage):
    '''
    HELLO message
    '''

    def __init__(self, from_router: bool) -> None:
        '''
        Constructor

        Inputs:
          from_router (bool): whether the message is sent by chirouter
            (True) or to chirouter (False).
        '''
        if from_router:
            subtype = ChirouterMessage.SUBTYPE_FROM_ROUTER
        else:
            subtype = ChirouterMessage.SUBTYPE_TO_ROUTER
        super().__init__(msg_type=ChirouterMessage.MSG_TYPE_HELLO,
                         subtype=subtype)

    def pack(self) -> bytes:
        '''
        See ChirouterMessage.pack
        '''
        return self._pack()


class ChirouterMessageRouters(ChirouterMessage):
    '''
    ROUTERS message: specifies how many routers chirouter will manage.
    '''

    def __init__(self, num_routers: int) -> None:
        '''
        Constructor

        Inputs:
          num_routers (int): number of routers.
        '''
        super().__init__(msg_type=ChirouterMessage.MSG_TYPE_ROUTERS,
                         subtype=ChirouterMessage.SUBTYPE_NONE)

        self.num_routers = num_routers

    def pack(self) -> bytes:
        '''
        See ChirouterMessage.pack
        '''
        return self._pack(struct.pack("!B", self.num_routers))


class ChirouterMessageRouter(ChirouterMessage):
    '''
    ROUTER message: specifies the basic parameters of a single router.
    '''

    def __init__(self, rid: int, num_interfaces: int, len_rtable: int,
                 name: str) -> None:
        '''
        Constructor

        Inputs:
          rid (int): router ID.
          num_interfaces (int): number of interfaces in the router.
          len_rtable (int): number of entries in the routing table.
          name (str): name of the router.
        '''
        super().__init__(msg_type=ChirouterMessage.MSG_TYPE_ROUTER,
                         subtype=ChirouterMessage.SUBTYPE_NONE)

        self.rid = rid
        self.num_interfaces = num_interfaces
        self.len_rtable = len_rtable
        self.name = name

    def pack(self) -> bytes:
        '''
        See ChirouterMessage.pack
        '''
        name = bytes(self.name, "utf-8")
        payload = struct.pack("!BBB", self.rid, self.num_interfaces,
                              self.len_rtable)
        return self._pack(payload + name)


class ChirouterMessageInterface(ChirouterMessage):
    '''
    INTERFACE message: specifies a single interface in a router.
    '''

    def __init__(self, rid: int, iface_id: int, hwaddr: bytes, ipaddr: bytes,
                 name: str) -> None:
        '''
        Constructor

        Inputs:
          rid (int): router ID.
          iface_id (int): interface ID.
          hwaddr (bytes): MAC address of the interface (6 bytes).
          ipaddr (bytes): IPv4 address of the interface (4 bytes).
          name (str): name of the interface.
        '''
        super().__init__(msg_type=ChirouterMessage.MSG_TYPE_INTERFACE,
                         subtype=ChirouterMessage.SUBTYPE_NONE)

        self.rid = rid
        self.iface_id = iface_id
        self.hwaddr = hwaddr
        self.ipaddr = ipaddr
        self.name = name

    def pack(self) -> bytes:
        '''
        See ChirouterMessage.pack
        '''
        name = bytes(self.name, "utf-8")
        payload = struct.pack("!BB", self.rid, self.iface_id)
        return self._pack(payload + self.hwaddr + self.ipaddr + name)


class ChirouterMessageRTableEntry(ChirouterMessage):
    '''
    ROUTING TABLE ENTRY message: specifies a single entry in the routing
    table of a router.
    '''

    def __init__(self, rid: int, iface_id: int, dest: bytes, mask: bytes,
                 gw: bytes, metric: int) -> None:
        '''
        Constructor

        Inputs:
          rid (int): router ID.
          iface_id (int): ID of the interface for this entry.
          dest (bytes): destination network (4 bytes).
          mask (bytes): destination network mask (4 bytes).
          gw (bytes): gateway (4 bytes; all zeroes if there is no gateway).
          metric (int): metric of this entry.
        '''
        super().__init__(msg_type=ChirouterMessage.MSG_TYPE_RTABLE_ENTRY,
                         subtype=ChirouterMessage.SUBTYPE_NONE)

        self.rid = rid
        self.iface_id = iface_id
        self.dest = dest
        self.mask = mask
        self.gw = gw
        self.metric = metric

    def pack(self) -> bytes:
        '''
        See ChirouterMessage.pack
        '''
        payload = struct.pack("!BBH", self.rid, self.iface_id, self.metric)
        return self._pack(payload + self.dest + self.mask + self.gw)


class ChirouterMessageEndConfig(ChirouterMessage):
    '''
    END CONFIG message: indicates that all the configuration has been sent.
    '''

    def __init__(self) -> None:
        '''
        Constructor
        '''
        super().__init__(msg_type=ChirouterMessage.MSG_TYPE_END_CONFIG,
                         subtype=ChirouterMessage.SUBTYPE_NONE)

    def pack(self) -> bytes:
        '''
        See ChirouterMessage.pack
        '''
        return self._pack()


class ChirouterMessageEthernetFrame(ChirouterMessage):
    '''
    ETHERNET FRAME message: an Ethernet frame sent or received by a router.
    '''

    # Length of the fixed-length part of the payload (router ID,
    # interface ID, and frame length)
    FIXED_LEN = 4

    def __init__(self, rid: int, iface_id: int, frame_len: int, frame: bytes,
                 from_router: bool) -> None:
        '''
        Constructor

        Inputs:
          rid (int): router ID.
          iface_id (int): interface ID.
          frame_len (int): length of the frame.
          frame (bytes): the frame.
          from_router (bool): whether the frame was sent by the router (True)
            or received by the router (False).
        '''
        if from_router:
            subtype = ChirouterMessage.SUBTYPE_FROM_ROUTER
        else:
            subtype = ChirouterMessage.SUBTYPE_TO_ROUTER
        super().__init__(msg_type=ChirouterMessage.MSG_TYPE_ETHERNET_FRAME,
                         subtype=subtype)

        self.rid = rid
        self.iface_id = iface_id
        self.frame_len = frame_len
        self.frame = frame

    def pack(self) -> bytes:
        '''
        See ChirouterMessage.pack
        '''
        payload = struct.pack("!BBH", self.rid, self.iface_id, self.frame_len)
        return self._pack(payload + self.frame)

    @classmethod
    def from_buffer(cls, buf: bytes) -> ChirouterMessageEthernetFrame:
        '''
        Parses an ETHERNET FRAME message.

        Inputs:
          buf (bytes): a complete ETHERNET FRAME message, including its header.

        Returns:
          (ChirouterMessageEthernetFrame) the message.
        '''
        fields_end = MSG_HDR_LEN + cls.FIXED_LEN
        (msg_type, msg_subtype, _,
         rid, iface_id, frame_len) = struct.unpack("!BBHBBH", buf[:fields_end])

        assert msg_type == ChirouterMessage.MSG_TYPE_ETHERNET_FRAME

        from_router = (msg_subtype == ChirouterMessage.SUBTYPE_FROM_ROUTER)
        frame = buf[fields_end:fields_end + frame_len]

        return cls(rid, iface_id, frame_len, frame, from_router)


class ChirouterClient:
    '''
    A connection to chirouter, which can be used to send it the configuration
    of the routers in a topology, and then to exchange Ethernet frames with it.
    '''

    def __init__(self, hostname: str, port: int, topology: Topology) -> None:
        '''
        Constructor (does not connect to chirouter; see connect)

        Inputs:
          hostname (str): host where chirouter is running.
          port (int): port where chirouter is listening.
          topology (Topology): the topology with the routers.
        '''
        self.connected = False
        self.hostname = hostname
        self.port = port
        self.topology = topology
        self.conn: socket.socket | None = None

        # The router and interface IDs assigned to the routers and
        # interfaces in the topology (set by connect)
        self.router_ids: dict[Router, int] = {}
        self.router_nodes: dict[int, Router] = {}
        self.iface_ids: dict[Interface, tuple[int, int]] = {}
        self.iface_nodes: dict[tuple[int, int], Interface] = {}

    def connect(self) -> None:
        '''
        Connects to chirouter, and sends it the configuration of all the
        routers in the topology. The MAC addresses of the routers' interfaces
        must already be set in the topology.

        Raises OSError if chirouter cannot be reached.
        '''
        self.conn = socket.create_connection((self.hostname, self.port))

        self.send_msg(ChirouterMessageHello(from_router=False))
        next(self.received_messages)

        self.send_msg(ChirouterMessageRouters(self.topology.num_routers))

        for rid, router in enumerate(self.topology.routers):
            self.router_ids[router] = rid
            self.router_nodes[rid] = router
            self._send_router_config(rid, router)

        self.send_msg(ChirouterMessageEndConfig())
        self.connected = True

    def _send_router_config(self, rid: int, router: Router) -> None:
        '''
        Sends the ROUTER, INTERFACE, and ROUTING TABLE ENTRY messages
        for a single router.

        Inputs:
          rid (int): ID of the router.
          router (Router): the router.
        '''
        self.send_msg(ChirouterMessageRouter(
            rid=rid,
            num_interfaces=router.num_interfaces,
            len_rtable=router.len_rtable,
            name=router.name))

        for iface_id, iface_name in enumerate(sorted(router.interfaces)):
            iface = router.interfaces[iface_name]
            self.iface_ids[iface] = (rid, iface_id)
            self.iface_nodes[(rid, iface_id)] = iface

            if iface.hwaddr is None:
                hwaddr = bytes(6)
            else:
                hwaddr = iface.hwaddr_packed

            self.send_msg(ChirouterMessageInterface(rid=rid,
                                                    iface_id=iface_id,
                                                    hwaddr=hwaddr,
                                                    ipaddr=iface.ip_packed,
                                                    name=iface.name))

        for rte in router.rtable:
            iface = router.interfaces[rte.iface]
            _, iface_id = self.iface_ids[iface]

            self.send_msg(ChirouterMessageRTableEntry(
                rid=rid,
                iface_id=iface_id,
                dest=rte.network.packed,
                mask=rte.network.netmask.packed,
                gw=rte.gateway_addr.packed,
                metric=rte.metric))

    @property
    def received_messages(self) -> Iterator[ChirouterMessage | None]:
        '''
        The messages received from chirouter (as a generator that yields
        each message as it arrives, and stops when chirouter closes the
        connection). Messages that are not supported (see
        ChirouterMessage.from_buffer) are yielded as None.
        '''
        assert self.conn is not None

        buf = b""
        while True:
            data = self.conn.recv(RECV_SIZE)
            if not data:
                return None
            buf += data

            while len(buf) >= MSG_HDR_LEN:
                _, _, payload_len = struct.unpack("!BBH", buf[:MSG_HDR_LEN])
                msg_len = MSG_HDR_LEN + payload_len
                if len(buf) < msg_len:
                    break
                yield ChirouterMessage.from_buffer(buf[:msg_len])
                buf = buf[msg_len:]

    def send_msg(self, msg: ChirouterMessage) -> bool:
        '''
        Sends a message to chirouter.

        Inputs:
          msg (ChirouterMessage): the message.

        Returns:
          (bool) True if the message was sent, False if chirouter closed
          the connection. Other errors raise an OSError exception.
        '''
        assert self.conn is not None

        try:
            self.conn.sendall(msg.pack())
        except OSError as e:
            if e.errno == errno.EPIPE:
                return False
            else:
                raise e

        return True
