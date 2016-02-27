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

TOPOLOGY_DIR=$(readlink -f $TOPOLOGY_DIR)
export PYTHONPATH=$(pwd)/src/network:$PYTHONPATH

./lib/pox/pox.py log --format="[%(asctime)s] %(levelname)-8s %(module)s %(message)s" log.level --DEBUG --packet=CRITICAL chirouter.network_simulator.pox_controller --topology-dir=$TOPOLOGY_DIR
