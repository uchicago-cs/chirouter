#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.util import quietRun
from mininet.moduledeps import pathCheck

from sys import exit
import os.path
from subprocess import Popen, STDOUT, PIPE

import sys

import yaml

IPBASE = '10.3.0.0/16'

class CMSC233Topo( Topo ):
    "CMSC 233 Simple-Router Topology"
    
    def __init__( self,  yaml_obj, net_context, *args, **kwargs):
        Topo.__init__( self, *args, **kwargs )
        self.recursive_switch_counter = 12
        self.recursive_topo_create(yaml_obj, net_context, None, None, None, None, None)
        return

    def recursive_topo_create(self, yaml_rep, net_context, parent_ip, parent_mask, parent_subnet, parent_iface, parent_node):
        if yaml_rep["subnet"]:
            if len(yaml_rep["hosts"]) == 1:
                yaml_host = yaml_rep["hosts"][0]
                host_name = yaml_host["name"]

                root = self.addHost(host_name)

                net_context["host_ip_map"][root] = yaml_host["ip"]
                net_context["host_default_gateway_map"][root] = parent_ip

                if "http" in yaml_host and yaml_host["http"]:
                    net_context["http_servers"].append(host_name)

                self.addLink(root, parent_node, intfName2 = parent_iface)
            else:
                switch = self.addSwitch("switch"+str(self.recursive_switch_counter))
                self.recursive_switch_counter+=1
                for yaml_host in yaml_rep["hosts"]:
                    host_name = yaml_host["name"]

                    root = self.addHost(host_name)

                    net_context["host_ip_map"][root] = yaml_host["ip"]
                    net_context["host_subnet_ip_map"][root] = parent_subnet
                    net_context["host_subnet_mask_map"][root] = parent_mask
                    net_context["host_default_gateway_map"][root] = parent_ip

                    if "http" in yaml_host and yaml_host["http"]:
                        net_context["http_servers"].append(host_name)

                    self.addLink(root, switch)

                self.addLink(switch, parent_node, intfName2 = parent_iface)
                    
        else:
            cur_router = self.addSwitch(yaml_rep["router_name"])
            for interface in yaml_rep["interfaces"]:
                if interface["gateway"]:
                    gateway_if = yaml_rep["router_name"]+"-"+interface["name"]
                    self.addLink(cur_router, parent_node, intfName1 = gateway_if, intfName2 = parent_iface)
                else:
                    cur_iface_name  = yaml_rep["router_name"]+"-"+interface["name"]
                    self.recursive_topo_create(interface["child"], net_context, interface["ip"], interface["mask"], interface["subnet_ip"], cur_iface_name, cur_router)

def set_yaml_default_route(host, net_context):
    info('*** setting yaml default gateway of host %s\n' % host.name)
    routerip = net_context["host_default_gateway_map"][host.name]
    print host.name, routerip
    host.cmd('route add default gw %s dev %s-eth0' % (routerip, host.name))
    ips = net_context["host_ip_map"][host.name].split(".") 
    host.cmd('route del -net %s.0.0.0/8 dev %s-eth0' % (ips[0], host.name))

def starthttp( host ):
    "Start simple Python web server on hosts"
    print ('*** Starting SimpleHTTPServer on host %s' % host )
    print host.cmd( 'nohup python2.7 ./scripts/webserver.py %s &' % (host.name) )

def stophttp():
    "Stop simple Python web servers"
    info( '*** Shutting down stale SimpleHTTPServers', 
          quietRun( "pkill -9 -f SimpleHTTPServer" ), '\n' )    
    info( '*** Shutting down stale webservers', 
          quietRun( "pkill -9 -f webserver.py" ), '\n' ) 


def init_yaml_objects(net, net_context):
    for host_name in net_context["host_ip_map"].keys():
        host = net.get(host_name)
        hinft = host.defaultIntf()
        hinft.setIP('%s/8' % net_context["host_ip_map"][host_name])
        set_yaml_default_route(host, net_context)
    for host_name in net_context["host_subnet_ip_map"].keys():
        host = net.get(host_name)
        host.cmd('route add -net %s netmask %s %s-eth0' % (net_context["host_subnet_ip_map"][host_name], net_context["host_subnet_mask_map"][host_name], host_name))
    for host_name in net_context["http_servers"]:
        starthttp(net.get(host_name))

def make_net_from_yaml(yaml_obj):
    "Create a network for cs233 using the specified yaml topology file."
    net_context = {}
    net_context["host_ip_map"] = {}
    net_context["host_subnet_ip_map"] = {}
    net_context["host_subnet_mask_map"] = {}
    net_context["host_default_gateway_map"] = {}
    net_context["http_servers"] = []
    topo = CMSC233Topo(yaml_obj, net_context)
    info( '*** Creating network\n' )
    net = Mininet( topo=topo, controller=RemoteController, ipBase=IPBASE )
    net.start()
    stophttp()
    init_yaml_objects(net, net_context)

    return net
    
def run_net_in_cli(net):
    CLI( net )
    net.stop()
    stophttp()

if __name__ == '__main__':
    setLogLevel( 'info' )
    yaml_string = open(sys.argv[1], 'r').read()
    yaml_obj = yaml.load(yaml_string)
    net = make_net_from_yaml(yaml_obj)
    run_net_in_cli(net)
