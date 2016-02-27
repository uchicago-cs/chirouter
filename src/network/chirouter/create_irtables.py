#!/usr/bin/python

import yaml
import sys
import os

def generate_irface_tables(topology_dir, yaml_obj):
    router_dpid_list = open("{}/router_dpid_list".format(topology_dir), "w")
    recursively_generate_irface_tables(topology_dir, yaml_obj, router_dpid_list)

def recursively_generate_irface_tables(topology_dir, yaml_obj, router_dpid_list):
    if yaml_obj["subnet"] == False:
        router_dpid_list.write(yaml_obj["dpid"]+"\n")
        #We have a router
        iface_file = open("{}/itable{}".format(topology_dir, yaml_obj["dpid"]), "w")
        rface_file = open("{}/rtable{}".format(topology_dir, yaml_obj["dpid"]), "w")
        for interface in yaml_obj["interfaces"]:
            iface_file.write(interface["ip"]+" "+interface["name"]+"\n")
            if interface["gateway"] == False:
                rface_file.write(interface["subnet_ip"]+" "+interface["gateway_ip"]+" "+interface["mask"]+" "+interface["name"]+"\n")
                recursively_generate_irface_tables(topology_dir, interface["child"], router_dpid_list)
            else:
                rface_file.write("0.0.0.0 " + interface["gateway_ip"] + " 0.0.0.0 " + interface["name"]+"\n")

if __name__ == '__main__':
    topology_dir = sys.argv[1]
    yaml_string = open("{}/topology.yaml".format(topology_dir), 'r').read()
    yaml_obj = yaml.load(yaml_string)
    generate_irface_tables(topology_dir, yaml_obj)
    print ("Created iface and routing tables for %s" % (topology_dir))
