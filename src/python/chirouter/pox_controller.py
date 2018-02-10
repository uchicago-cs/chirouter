import threading
import os.path
import sys

from chirouter.client import ChirouterClient, ChirouterMessageEthernetFrame
import chirouter.topology as topo

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet

log = core.getLogger()


class RouterController(object):

    def __init__(self, connection, client, topo_node):
        self.connection = connection
        self.client = client
        self.topo_node = topo_node
        self.port_iface = {}
        self.iface_port = {}

        for port in connection.features.ports:
            if not "-" in port.name:
                continue
            
            node_name, iface_name = port.name.split("-")

            if iface_name in topo_node.interfaces:
                iface = topo_node.interfaces[iface_name]
                iface.hwaddr = str(port.hw_addr)
                self.port_iface[port.port_no] = iface
                self.iface_port[iface] = port.port_no

        connection.addListeners(self)

    def forward_frame(self, iface, frame):
        of_packet_out = of.ofp_packet_out()
        of_packet_out.data = bytes(frame)
        of_packet_out.in_port = of.OFPP_NONE
        output_port = self.iface_port[iface]
        action = of.ofp_action_output(port=output_port)
        of_packet_out.actions.append(action)
        self.connection.send(of_packet_out)

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            # Ignoring incomplete packet
            return

        # TODO: Filter unnecessary traffic

        topo_iface = self.port_iface[event.port]
        rid, iface_id = self.client.iface_ids[topo_iface]
        raw_packet = packet.pack()

        msg = ChirouterMessageEthernetFrame(rid=rid,
                                            iface_id=iface_id,
                                            frame_len=len(raw_packet),
                                            frame=raw_packet,
                                            from_router=False)

        self.client.send_msg(msg)


class SwitchController(object):
    """
    A SwitchController object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

    def resend_packet(self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
        "packet_in" is the ofp_packet_in object the switch had sent to the
        controller due to a table-miss.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def act_like_hub(self, packet, packet_in):
        """
        Implement hub-like behavior -- send all packets to all ports besides
        the input port.
        """

        # We want to output to all ports -- we do that using the special
        # OFPP_ALL port as the output port.  (We could have also used
        # OFPP_FLOOD.)
        self.resend_packet(packet_in, of.OFPP_ALL)

    def _handle_PacketIn(self, event):
        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            # og.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.

        self.act_like_hub(packet, packet_in)

    def shutdown_controller(self):
        pass


def launch(topo_file, chirouter_host="localhost", chirouter_port="23300"):
    if not os.path.exists(topo_file):
        print "ERROR: Topology file %s does not exists" % topo_file
        sys.exit(1)

    topology = topo.Topology.from_json(open(topo_file))
    client = ChirouterClient(chirouter_host, int(chirouter_port), topology)
    router_controllers = {}

    def process_messages():
        for msg in client.received_messages:
            router = client.router_nodes[msg.rid]
            iface = client.iface_nodes[(msg.rid, msg.iface_id)]
            controller = router_controllers[router]
            controller.forward_frame(iface, msg.frame)
        print "chirouter has closed connection"

    def start_switch(event):
        dpid = event.connection.dpid
        log.debug("Controlling %s (dpid: %i)" % (event.connection, dpid))

        node = topology.nodes[dpid]
        if isinstance(node, topo.Router):
            controller = RouterController(event.connection, client, node)
            router_controllers[node] = controller
            log.debug("Made new RouterController")

            if len(router_controllers) == topology.num_routers:
                log.debug("All RouterControllers created. Connecting to chirouter...")

                client.connect()
    
                message_thread = threading.Thread(target=process_messages)
                message_thread.daemon = True
                message_thread.start()

        elif isinstance(node, topo.Switch):

            controller = SwitchController(event.connection)
            log.debug("Made new SwitchController")

    def stop_switch(event):
        log.debug("Stopping %s" % (event.connection,))
        if (event.connection in router_controllers):
            router_controllers[event.connection].shutdown_controller()

    core.openflow.miss_send_len = 0xffff
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    core.openflow.addListenerByName("ConnectionDown", stop_switch)
