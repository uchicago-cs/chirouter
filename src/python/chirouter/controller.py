import threading

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.app.ofctl import api as ofctl_api
from ryu import cfg

from chirouter.client import ChirouterClient, ChirouterMessageEthernetFrame
import chirouter.topology as topo


class Chirouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Chirouter, self).__init__(*args, **kwargs)

        topology_file = cfg.CONF['chirouter']['topology_file']
        chirouter_host = cfg.CONF['chirouter']['host']
        chirouter_port = cfg.CONF['chirouter']['port']

        self.topology = topo.Topology.from_json(open(topology_file))
        self.client = ChirouterClient(chirouter_host, int(chirouter_port), self.topology)

        self.switch_dpids = set()
        self.router_dpids = set()
        self.of2topo = {}
        self.topo2of = {}
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        dpid = ev.msg.datapath.id

        if dpid in self.switch_dpids:
            self.__switch_packet_in_handler(ev)
        elif dpid in self.router_dpids:
            self.__router_packet_in_handler(ev)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def __router_packet_in_handler(self, ev):
        dpid = ev.msg.datapath.id
        port = ev.msg.match['in_port']

        topo_iface = self.of2topo[(dpid, port)]
        rid, iface_id = self.client.iface_ids[topo_iface]

        raw_packet = ev.msg.data

        msg = ChirouterMessageEthernetFrame(rid=rid,
                                            iface_id=iface_id,
                                            frame_len=len(raw_packet),
                                            frame=raw_packet,
                                            from_router=False)

        self.client.send_msg(msg)

    def __switch_packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src
        print(dst[0])
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        match = parser.OFPMatch(in_port=in_port)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  match=match, actions=actions, data=data)
        datapath.send_msg(out)

    def forward_frame(self, dpid, out_port, frame):
        datapath = ofctl_api.get_datapath(self, dpid=dpid)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=ofproto.OFPP_ANY)
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, match=match,
                                  actions=actions, data=bytes(frame))

        datapath.send_msg(out)

    def process_messages(self):
        for msg in self.client.received_messages:
            iface = self.client.iface_nodes[(msg.rid, msg.iface_id)]
            dpid, out_port = self.topo2of[iface]
            self.forward_frame(dpid, out_port, msg.frame)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        topo_node = self.topology.nodes.get(dpid)

        if topo_node is None:
            self.logger.error(f"Received information about unknown switch id={dpid}")
            return

        self.logger.info(f"Received information about switch id={dpid}")

        if isinstance(topo_node, topo.Router):
            self.logger.info(f"Switch {dpid} is a chirouter-managed router")
            self.router_dpids.add(dpid)

            # Request information about the router's ports
            msg = parser.OFPPortDescStatsRequest(datapath=datapath)
            result = ofctl_api.send_msg(
                self, msg,
                reply_cls=parser.OFPPortDescStatsReply,
                reply_multi=True)
            for reply in result:
                for port in reply.body:
                    port_name = port.name.decode('UTF-8')

                    if not "-" in port_name:
                        continue

                    node_name, iface_name = port_name.split("-")

                    if iface_name in topo_node.interfaces:
                        self.logger.info(f"Processing port {port_name}")
                        iface = topo_node.interfaces[iface_name]
                        self.of2topo[(dpid, port.port_no)] = iface
                        self.topo2of[iface] = (dpid, port.port_no)
                        iface.hwaddr = str(port.hw_addr)

            if len(self.router_dpids) == self.topology.num_routers:
                self.logger.info("All routers accounted for. Connecting to chirouter...")

                self.client.connect()

                message_thread = threading.Thread(target=self.process_messages)
                message_thread.daemon = True
                message_thread.start()

        elif isinstance(topo_node, topo.Switch):
            self.logger.info(f"Switch {dpid} is a regular switch")
            self.switch_dpids.add(dpid)

        print()

        # Install table-miss flow entry (so frames are sent to
        # the controller for processing)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

