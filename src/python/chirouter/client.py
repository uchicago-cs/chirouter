import socket
import struct
import errno

from chirouter.topology import Topology

class ChirouterClientException(Exception):
    pass

class ChirouterMessage(object):
    MSG_TYPE_HELLO = 1
    MSG_TYPE_ROUTERS = 2
    MSG_TYPE_ROUTER = 3
    MSG_TYPE_INTERFACE = 4
    MSG_TYPE_RTABLE_ENTRY = 5
    MSG_TYPE_END_CONFIG = 6
    MSG_TYPE_ETHERNET_FRAME = 7


    SUBTYPE_NONE = 0
    SUBTYPE_TO_ROUTER = 1
    SUBTYPE_FROM_ROUTER = 2

    def __init__(self, msg_type, subtype):
        self.type = msg_type
        self.subtype = subtype

    @staticmethod
    def from_buffer(buf):
        view = memoryview(buf)
        msg_type, msg_subtype, payload_len = struct.unpack("!BBH", view[:4])

        if msg_type == ChirouterMessage.MSG_TYPE_HELLO:
            if msg_subtype == ChirouterMessage.SUBTYPE_TO_ROUTER:
                return ChirouterMessageHello(from_router=False)
            elif msg_subtype == ChirouterMessage.SUBTYPE_FROM_ROUTER:
                return ChirouterMessageHello(from_router=True)
        elif msg_type == ChirouterMessage.MSG_TYPE_ETHERNET_FRAME:
            return ChirouterMessageEthernetFrame.from_buffer(buf)


        return None

    def _pack(self, payload_length=0, payload=None):
        assert ((payload_length > 0 and len(payload) == payload_length) or
                (payload_length == 0 and payload is None))

        if payload_length == 0:
            return struct.pack("!BBH", self.type, self.subtype, payload_length)
        else:
            return struct.pack("!BBH", self.type, self.subtype, payload_length) + payload


class ChirouterMessageHello(ChirouterMessage):
    def __init__(self, from_router):
        if from_router:
            ChirouterMessage.__init__(self,
                                      msg_type=ChirouterMessage.MSG_TYPE_HELLO,
                                      subtype=ChirouterMessage.SUBTYPE_FROM_ROUTER)
        else:
            ChirouterMessage.__init__(self,
                                      msg_type=ChirouterMessage.MSG_TYPE_HELLO,
                                      subtype=ChirouterMessage.SUBTYPE_TO_ROUTER)

    def pack(self):
        return self._pack()


class ChirouterMessageRouters(ChirouterMessage):
    def __init__(self, num_routers):
        ChirouterMessage.__init__(self,
                                  msg_type=ChirouterMessage.MSG_TYPE_ROUTERS,
                                  subtype=ChirouterMessage.SUBTYPE_NONE)

        self.num_routers = num_routers

    def pack(self):
        payload = struct.pack("!B", self.num_routers)
        return self._pack(1, payload)


class ChirouterMessageRouter(ChirouterMessage):
    def __init__(self, rid, num_interfaces, len_rtable, name):
        ChirouterMessage.__init__(self,
                                  msg_type=ChirouterMessage.MSG_TYPE_ROUTER,
                                  subtype=ChirouterMessage.SUBTYPE_NONE)

        self.rid = rid
        self.num_interfaces = num_interfaces
        self.len_rtable = len_rtable
        self.name = name

    def pack(self):
        payload = struct.pack("!BBB", self.rid, self.num_interfaces, self.len_rtable) + str(self.name)
        return self._pack(3 + len(self.name), payload)


class ChirouterMessageInterface(ChirouterMessage):
    def __init__(self, rid, iface_id, hwaddr, ipaddr, name):
        ChirouterMessage.__init__(self,
                                  msg_type=ChirouterMessage.MSG_TYPE_INTERFACE,
                                  subtype=ChirouterMessage.SUBTYPE_NONE)

        self.rid = rid
        self.iface_id = iface_id
        self.hwaddr = hwaddr
        self.ipaddr = ipaddr
        self.name = name

    def pack(self):
        payload = struct.pack("!BB", self.rid, self.iface_id) + self.hwaddr + self.ipaddr + str(self.name)
        return self._pack(12 + len(self.name), payload)

class ChirouterMessageRTableEntry(ChirouterMessage):
    def __init__(self, rid, iface_id, dest, mask, gw, metric):
        ChirouterMessage.__init__(self,
                                  msg_type=ChirouterMessage.MSG_TYPE_RTABLE_ENTRY,
                                  subtype=ChirouterMessage.SUBTYPE_NONE)

        self.rid = rid
        self.iface_id = iface_id
        self.dest = dest
        self.mask = mask
        self.gw = gw
        self.metric = metric

    def pack(self):
        payload = struct.pack("!BBH", self.rid, self.iface_id, self.metric)
        payload += self.dest + self.mask + self.gw
        return self._pack(16, payload)


class ChirouterMessageEndConfig(ChirouterMessage):
    def __init__(self):
        ChirouterMessage.__init__(self,
                                  msg_type=ChirouterMessage.MSG_TYPE_END_CONFIG,
                                  subtype=ChirouterMessage.SUBTYPE_NONE)

    def pack(self):
        return self._pack()


class ChirouterMessageEthernetFrame(ChirouterMessage):
    def __init__(self, rid, iface_id, frame_len, frame, from_router):

        if from_router:
            ChirouterMessage.__init__(self,
                                      msg_type=ChirouterMessage.MSG_TYPE_ETHERNET_FRAME,
                                      subtype=ChirouterMessage.SUBTYPE_FROM_ROUTER)
        else:
            ChirouterMessage.__init__(self,
                                      msg_type=ChirouterMessage.MSG_TYPE_ETHERNET_FRAME,
                                      subtype=ChirouterMessage.SUBTYPE_TO_ROUTER)
        self.rid = rid
        self.iface_id = iface_id
        self.frame_len = frame_len
        self.frame = frame

    def pack(self):
        payload = struct.pack("!BBH", self.rid, self.iface_id, self.frame_len) + self.frame
        return self._pack(4 + self.frame_len, payload)

    @classmethod
    def from_buffer(cls, buf):
        view = memoryview(buf)
        msg_type, msg_subtype, payload_len, rid, iface_id, frame_len = struct.unpack("!BBHBBH", view[:8])

        assert msg_type == ChirouterMessage.MSG_TYPE_ETHERNET_FRAME

        if msg_subtype == ChirouterMessage.SUBTYPE_FROM_ROUTER:
            from_router = True
        elif  msg_subtype == ChirouterMessage.SUBTYPE_TO_ROUTER:
            from_router = False

        return cls(rid, iface_id, frame_len, buf[8:8+frame_len], from_router)



class ChirouterClient(object):
    def __init__(self, hostname, port, topology):
        self.connected = False
        self.hostname = hostname
        self.port = port
        self.topology = topology
        self.conn = None

        self.router_ids = {}
        self.router_nodes = {}
        self.iface_ids = {}
        self.iface_nodes = {}

    def connect(self):
        self.conn = socket.create_connection((self.hostname, self.port))

        hello = ChirouterMessageHello(from_router=False)
        self.send_msg(hello)
        reply = self.received_messages.next()

        routers = ChirouterMessageRouters(self.topology.num_routers)
        self.send_msg(routers)

        rid = 0
        for router in self.topology.routers:
            self.router_ids[router] = rid
            self.router_nodes[rid] = router

            router_msg = ChirouterMessageRouter(rid=rid,
                                                num_interfaces=router.num_interfaces,
                                                len_rtable=router.len_rtable,
                                                name=router.name)

            self.send_msg(router_msg)

            iface_id = 0
            iface_names = sorted(router.interfaces.keys())

            for iface_name in iface_names:
                iface = router.interfaces[iface_name]
                self.iface_ids[iface] = (rid, iface_id)
                self.iface_nodes[(rid, iface_id)] = iface

                if iface.hwaddr is None:
                    hwaddr = bytearray([0,0,0,0,0,0])
                else:
                    hwaddr = iface.hwaddr_packed

                interface_msg = ChirouterMessageInterface(rid = rid,
                                                          iface_id = iface_id,
                                                          hwaddr = hwaddr,
                                                          ipaddr = iface.ip_packed,
                                                          name = iface.name
                                                          )

                self.send_msg(interface_msg)

                iface_id += 1

            for rte in router.rtable:
                iface = router.interfaces[rte.iface]
                rid, iface_id = self.iface_ids[iface]

                rtable_msg = ChirouterMessageRTableEntry(rid = rid,
                                                         iface_id = iface_id,
                                                         dest = rte.network.packed,
                                                         mask = rte.network.netmask.packed,
                                                         gw = rte.gateway_addr.packed,
                                                         metric=rte.metric
                                                        )

                self.send_msg(rtable_msg)

            rid += 1

        done_msg = ChirouterMessageEndConfig()
        self.send_msg(done_msg)
        self.connected = True



    @property
    def received_messages(self):

        msg_buffer = bytearray(4096)

        bufpos = 0

        reading_header = True

        while True:
            recv_buffer = self.conn.recv(4096)

            if len(recv_buffer) == 0:
                raise StopIteration

            recv_buffer = bytearray(recv_buffer)
            for b in recv_buffer:
                msg_buffer[bufpos] = b
                bufpos += 1

                if reading_header and bufpos == 4:
                    # We have a header
                    _, _, payload_len = struct.unpack("!BBH", msg_buffer[:4])
                    reading_header = False

                if not reading_header and bufpos == (payload_len + 4):
                    msg = ChirouterMessage.from_buffer(msg_buffer)
                    yield msg
                    reading_header = True
                    bufpos = 0
                    payload_len = 0

    def send_msg(self, msg):
        packed_msg = msg.pack()

        try:
            self.conn.sendall(packed_msg)
        except IOError, e:
            if e.errno == errno.EPIPE:
                return False
            else:
                raise e

        return True

if __name__ == "__main__":
    topology = Topology.from_json(open("basic.json"))

    c = ChirouterClient("localhost", 23300, topology)

    c.connect()