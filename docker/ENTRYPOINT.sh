#!/usr/bin/env bash

# Disable IPv6 on all interfaces in the container. Otherwise, the kernel
# sends IPv6 messages (router solicitations, etc.) on the routers'
# interfaces, which would be relayed to chirouter.
sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
sysctl -q -w net.ipv6.conf.default.disable_ipv6=1

if [ $# -eq 0 ]; then
    # If no parameters are provided, run bash
    bash
elif [ $# -eq 1 ]; then
    # If there is one parameter, run mininet with the specified topology
    /chirouter/run-mininet topologies/$1.json --chirouter host.docker.internal:23320
else
    echo "Error: This container accepts at most one parameter (a chirouter topology)"
fi
