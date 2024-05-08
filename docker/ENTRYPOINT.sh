#!/usr/bin/env bash

# We need to manually start ovsdb-server and ovs-vswitch (instead
# of running "service openvswitch-switch start") because the
# systemd scripts will attempt to load the openvswitch module,
# but the Linux kernel shipped with Docker Desktop has openvswitch
# built into the kernel, and not as a separate module,
# so running "service openvswitch-switch start" will fail.
#
# (see https://github.com/docker/for-mac/issues/7151)

ovsdb-tool create

mkdir -p /var/run/openvswitch/

ovsdb-server /etc/openvswitch/conf.db -vconsole:emer -vsyslog:err -vfile:info \
  --remote=punix:/var/run/openvswitch/db.sock --private-key=db:Open_vSwitch,SSL,private_key \
  --certificate=db:Open_vSwitch,SSL,certificate --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
  --no-chdir --log-file=/var/log/openvswitch/ovsdb-server.log \
  --pidfile=/var/run/openvswitch/ovsdb-server.pid --detach

ovs-vswitchd unix:/var/run/openvswitch/db.sock -vconsole:emer -vsyslog:err \
  -vfile:info --mlockall --no-chdir --log-file=/var/log/openvswitch/ovs-vswitchd.log \
  --pidfile=/var/run/openvswitch/ovs-vswitchd.pid --detach

if [ $# -eq 0 ]; then
    # If no parameters are provided, run bash
    bash
elif [ $# -eq 1 ]; then
    # If there is one parameter, run mininet with the specified topology
    /chirouter/run-mininet topologies/$1.json --chirouter host.docker.internal:23320
else
    echo "Error: This container accepts at most one parameter (a chirouter topology)"
fi
