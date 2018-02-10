import sys

from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.util import quietRun

from chirouter.client import ChirouterClient
from chirouter.topology import Topology

class POXController(Controller):
    def __init__( self, name, pox_location, topo_file, chirouter, **kwargs):

        if chirouter is None:
            chirouter_host, chirouter_port = "localhost", 23300
        else:
            chirouter_host, chirouter_port = chirouter

        command = "python2 pox.py"

        params  = ["log.level", "--DEBUG", "--packet=CRITICAL", "--port=%s"]
        params += ["chirouter.pox_controller"]
        params += ["--topo-file=" + topo_file]
        params += ["--chirouter-host=" + chirouter_host]
        params += ["--chirouter-port=" + str(chirouter_port)]

        cargs = " ".join(params)

        Controller.__init__( self, name, cdir=pox_location,
                             command=command,
                             cargs=cargs, **kwargs)


def run(topo_file, chirouter, pox, pox_location):
    setLogLevel('info')

    with open(topo_file, "r") as f:
        topo = Topology.from_json(f)

    mn_topo = topo.to_mininet_topology()

    if pox is not None:
        # POX is running somewhere else. We connect to it.
        controller = RemoteController("c0", ip=pox[0], port=pox[1])
    else:
        # We launch POX ourselves
        controller = POXController("c0", pox_location, topo_file, chirouter)

    net = Mininet(topo=mn_topo, controller = controller)
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
                print "*** Starting SimpleHTTPServer on host %s" % mn_host.name
                mn_host.cmd('nohup python2.7 ./scripts/webserver.py %s &' % (mn_host.name))

    for r in topo.routers:
        mn_router = net.get(r.name)

        for intf_name, intf in r.interfaces.items():
            intf.hwaddr = mn_router.intf(r.name + "-" + intf_name).mac

    net.start()
    CLI( net )
    net.stop()
    
    info("*** Shutting down stale SimpleHTTPServers", 
          quietRun( "pkill -9 -f SimpleHTTPServer" ), "\n" )    
    info('*** Shutting down stale webservers', 
          quietRun( "pkill -9 -f webserver.py" ), "\n" ) 
