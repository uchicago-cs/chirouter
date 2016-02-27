#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 TOPOLOGY_DIR"
    exit 1
fi

TOPOLOGY_DIR=$1

if [[ ! -d $TOPOLOGY_DIR ]]; then
    echo "$TOPOLOGY_DIR is not a directory"
    exit 1
fi

if [[ ! -f "$TOPOLOGY_DIR/topology.yaml" || ! -f "$TOPOLOGY_DIR/router_dpid_list" ]]; then
    echo "$TOPOLOGY_DIR does not appear to be a topology directory"
    exit 1
fi

sudo python src/network/chirouter/network_simulator/__init__.py $TOPOLOGY_DIR/topology.yaml
