import sys

from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.util import quietRun

from chirouter.client import ChirouterClient
from chirouter.topology import Topology


def run(topo_file, controller, run_cli=True):

    setLogLevel('info')

    with open(topo_file, "r") as f:
        topo = Topology.from_json(f)

    mn_topo = topo.to_mininet_topology()

    net = Mininet(topo=mn_topo, controller=controller)
    for h in topo.hosts:
        mn_host = net.get(h.name)
        for iface in h.interfaces.values():
            iface_name = h.name + "-" + iface.name
            try:
                mn_iface = mn_host.intf(iface_name)
            except:
                raise Exception("Error fetching interface {} from {}".format(iface_name, h.name))

            mn_iface.setIP(iface.ip_with_prefixlen)

            if iface.gateway is not None:
                mn_host.cmd("route add default gw {} dev {}".format(str(iface.gateway), iface_name))
                
            if "httpd" in h.attrs:
                print("*** Starting SimpleHTTPServer on host %s" % mn_host.name)
                mn_host.cmd('nohup python3 ./scripts/webserver.py %s &' % (mn_host.name))

    for r in topo.routers:
        mn_router = net.get(r.name)

        for intf_name, intf in r.interfaces.items():
            intf.hwaddr = mn_router.intf(r.name + "-" + intf_name).mac

    net.start()
    if run_cli:
        CLI(net)
        net.stop()

        info("*** Shutting down stale SimpleHTTPServers",
              quietRun( "pkill -9 -f SimpleHTTPServer" ), "\n" )
        info('*** Shutting down stale webservers',
              quietRun( "pkill -9 -f webserver.py" ), "\n" )
    else:
        return net
