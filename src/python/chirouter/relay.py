# Relays Ethernet frames between the routers in the simulated network
# and chirouter.
#
# Each router in the topology is represented in Mininet by a set of
# interfaces with no IP configuration (see RouterNode), so the kernel
# ignores any frames that arrive on them. The relay opens a raw packet
# socket on each of these interfaces, and forwards every frame received
# on them to chirouter (using the chirouter protocol described in
# src/c/server.h). Frames sent by chirouter are sent out the corresponding
# interface.

import os
import select
import socket
import struct
import threading
from typing import Any

from mininet.log import info, error
from mininet.node import Switch

from chirouter.client import (MSG_HDR_LEN, ChirouterClient, ChirouterMessage,
                              ChirouterMessageEthernetFrame)
from chirouter.topology import Topology

# Protocol number for packet sockets that receive all frames
ETH_P_ALL = 0x0003

# Value of sll_pkttype for frames sent by us (packet sockets
# receive a copy of these)
PACKET_OUTGOING = 4

# Maximum number of bytes to read from a socket at a time (no frame or
# message is larger than this)
RECV_SIZE = 65536

# How long to wait (in seconds) for chirouter to close its end of the
# connection when stopping the relay
CLOSE_TIMEOUT = 1.0

# Offloads that must be disabled on all interfaces, so that the frames
# seen by the relay are regular Ethernet frames (no larger than
# 1514 bytes, and with correct checksums)
OFFLOADS = ["rx", "tx", "sg", "tso", "gso", "gro", "lro"]


def disable_offloads(node: Any, intf: Any) -> str | None:
    '''
    Disables offloads (see OFFLOADS) on an interface.

    This fails when the container runs under QEMU emulation (e.g., the arm64
    image on an x86_64 computer), since QEMU doesn't support the ioctl used
    by ethtool. In that case, the frames sent by the hosts may have
    incorrect TCP/UDP checksums, so TCP and UDP traffic through the routers
    won't work (see simulator.warn_offload_errors).

    Inputs:
      node (mininet.node.Node): the node the interface belongs to.
      intf (mininet.link.Intf or str): the interface.

    Returns:
      (str | None) None if the offloads were disabled, or a description
      of the error (ethtool's output) if they weren't.
    '''
    offloads = " ".join(f"{o} off" for o in OFFLOADS)
    output = node.cmd("ethtool -K {} {} 2>&1; echo $?".format(intf, offloads))

    # The last line of the output is ethtool's exit status
    lines = output.strip().splitlines()
    if lines and lines[-1].strip() == "0":
        return None

    details = " ".join(line.strip() for line in lines[:-1])
    return details or "ethtool failed"


class RouterNode(Switch):
    '''
    A chirouter-managed router. In Mininet, this is just a set of interfaces
    (in the root namespace, like the interfaces of a switch) with no IP
    configuration. The frames that arrive on them are relayed to chirouter
    by ChirouterRelay.
    '''

    def start(self, controllers: list[Any]) -> None:
        '''
        Configures the router's interfaces and brings them up (called by
        Mininet when the network is started). The interfaces whose offloads
        cannot be disabled are recorded in the offload_errors attribute
        (a dictionary mapping interface names to error descriptions).

        Inputs:
          controllers (list): OpenFlow controllers (ignored).

        Returns: nothing.
        '''
        self.offload_errors: dict[str, str] = {}
        for intf in self.intfList():
            if self.name in intf.name:
                # These interfaces are in the container's root namespace,
                # and the kernel must not process the frames that arrive
                # on them. Since they have no IP addresses, it doesn't, but
                # we also explicitly disable forwarding and ARP replies on
                # them (and IPv6 entirely), just in case.
                for sysctl in ("ipv6.conf.{}.disable_ipv6=1",
                               "ipv4.conf.{}.forwarding=0",
                               "ipv4.conf.{}.arp_ignore=8"):
                    self.cmd("sysctl -q -w net." + sysctl.format(intf))
                self.cmd("ip addr flush dev", intf)
                err = disable_offloads(self, intf)
                if err is not None:
                    self.offload_errors[str(intf)] = err
                self.cmd("ip link set", intf, "up")

    def connected(self) -> bool:
        '''
        Returns:
          (bool) whether the router is ready (always True, since the router
          doesn't need to connect to an OpenFlow controller).
        '''
        return True


class ChirouterRelay:
    '''
    Relays frames between the routers' interfaces and chirouter
    '''

    def __init__(self, topology: Topology, chirouter_host: str,
                 chirouter_port: int) -> None:
        '''
        Constructor (does not connect to chirouter; see start)

        Inputs:
          topology (Topology): the topology.
          chirouter_host (str): host where chirouter is running.
          chirouter_port (int): port where chirouter is listening.
        '''
        self.topology = topology
        self.client = ChirouterClient(chirouter_host, chirouter_port, topology)

        # Packet sockets, indexed by (router id, interface id),
        # and the (router id, interface id) of each socket, indexed
        # by its file descriptor
        self.sockets: dict[tuple[int, int], socket.socket] = {}
        self.fd_to_iface: dict[int, tuple[int, int]] = {}

        # Thread that relays the frames (and a pipe used to stop it)
        self.thread: threading.Thread | None = None
        self.stop_r, self.stop_w = os.pipe()

    def start(self) -> None:
        '''
        Connects to chirouter, sends it the configuration of the routers,
        and starts relaying frames (in a separate thread).

        The interfaces' MAC addresses (hwaddr) must already be set in the
        topology.

        Returns: nothing. Raises OSError if chirouter cannot be reached.
        '''
        info("*** Connecting to chirouter at {}:{}\n".format(
            self.client.hostname, self.client.port))
        self.client.connect()

        for (rid, iface_id), iface in self.client.iface_nodes.items():
            router = self.client.router_nodes[rid]
            ifname = "{}-{}".format(router.name, iface.name)

            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(ETH_P_ALL))
            sock.bind((ifname, 0))

            self.sockets[(rid, iface_id)] = sock
            self.fd_to_iface[sock.fileno()] = (rid, iface_id)

        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        '''
        Stops relaying frames, and closes the connection to chirouter.

        Returns: nothing.
        '''
        if self.thread is not None:
            os.write(self.stop_w, b"x")
            self.thread.join()
            self.thread = None

        for sock in self.sockets.values():
            sock.close()
        self.sockets = {}
        self.fd_to_iface = {}

        if self.client.conn is not None:
            # Read any data chirouter has already sent us before closing the
            # connection (closing a socket with unread data resets the
            # connection, which chirouter would report as an error)
            conn = self.client.conn
            conn.shutdown(socket.SHUT_WR)
            conn.settimeout(CLOSE_TIMEOUT)
            try:
                while conn.recv(RECV_SIZE):
                    pass
            except OSError:
                pass
            conn.close()
            self.client.conn = None

    def _run(self) -> None:
        '''
        Relays frames until the relay is stopped, or chirouter closes the
        connection (runs in its own thread).

        Returns: nothing.
        '''
        conn = self.client.conn
        assert conn is not None
        buf = bytearray()
        readers: list[socket.socket | int] = [conn, self.stop_r,
                                              *self.sockets.values()]

        while True:
            readable, _, _ = select.select(readers, [], [])

            if self.stop_r in readable:
                return

            for r in readable:
                if r is conn:
                    data = conn.recv(RECV_SIZE)
                    if not data:
                        error("*** chirouter closed the connection\n")
                        return
                    buf += data
                    buf = self._process_chirouter_data(buf)
                elif isinstance(r, socket.socket):
                    self._relay_frame_to_chirouter(r)

    def _relay_frame_to_chirouter(self, sock: socket.socket) -> None:
        '''
        Reads a frame from a router interface, and sends it to chirouter.

        Inputs:
          sock (socket): the packet socket of the interface.

        Returns: nothing.
        '''
        frame, addr = sock.recvfrom(RECV_SIZE)
        if addr[2] == PACKET_OUTGOING:
            return

        rid, iface_id = self.fd_to_iface[sock.fileno()]
        self.client.send_msg(ChirouterMessageEthernetFrame(
            rid=rid,
            iface_id=iface_id,
            frame_len=len(frame),
            frame=frame,
            from_router=False))

    def _process_chirouter_data(self, buf: bytearray) -> bytearray:
        '''
        Processes all the complete messages received from chirouter
        (sending the Ethernet frames they contain out the corresponding
        interfaces).

        Inputs:
          buf (bytearray): the data received from chirouter so far.

        Returns:
          (bytearray) the remaining data (the start of a message that
          hasn't been received completely yet).
        '''
        while len(buf) >= MSG_HDR_LEN:
            _, _, payload_len = struct.unpack("!BBH", buf[:MSG_HDR_LEN])
            msg_len = MSG_HDR_LEN + payload_len
            if len(buf) < msg_len:
                break

            msg = ChirouterMessage.from_buffer(bytes(buf[:msg_len]))
            del buf[:msg_len]

            if isinstance(msg, ChirouterMessageEthernetFrame):
                sock = self.sockets.get((msg.rid, msg.iface_id))
                if sock is None:
                    error("*** chirouter sent a frame on an unknown interface "
                          "(router {}, interface {})\n".format(
                              msg.rid, msg.iface_id))
                else:
                    sock.send(msg.frame)
            else:
                error("*** Received unexpected message from chirouter\n")

        return buf
