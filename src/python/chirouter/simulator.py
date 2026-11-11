# Creates and runs a simulated network with Mininet.
#
# The network is created from a topology file (see topology.py), and its
# routers are connected to chirouter (see relay.py).

from typing import Any

from mininet.log import setLogLevel, info, warn
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.util import quietRun

from chirouter.relay import ChirouterRelay, disable_offloads
from chirouter.topology import Host, Topology


def configure_host(net: Any, host: Host) -> dict[str, str]:
    '''
    Configures a host in the network: sets the IP address (and default
    gateway) of its interfaces and, if the host has the "httpd" attribute,
    starts a web server on it.

    Inputs:
      net (mininet.net.Mininet): the network.
      host (Host): the host.

    Returns:
      (dict of str to str) the interfaces whose offloads could not be
      disabled, and the errors (see disable_offloads). Raises a ValueError
      if one of the host's interfaces doesn't exist in the network.
    '''
    mn_host = net.get(host.name)
    offload_errors: dict[str, str] = {}

    # Hosts are in their own network namespace, so the container-wide
    # IPv6 settings don't apply to them
    mn_host.cmd("sysctl -q -w net.ipv6.conf.all.disable_ipv6=1")
    mn_host.cmd("sysctl -q -w net.ipv6.conf.default.disable_ipv6=1")

    for iface in host.interfaces.values():
        iface_name = host.name + "-" + iface.name
        if iface_name not in mn_host.nameToIntf:
            raise ValueError("Host {} has no interface {}"
                             .format(host.name, iface_name))

        mn_host.intf(iface_name).setIP(iface.ip_with_prefixlen)
        err = disable_offloads(mn_host, iface_name)
        if err is not None:
            offload_errors[iface_name] = err

        if iface.gateway is not None:
            mn_host.cmd("ip route add default via {} dev {}"
                        .format(iface.gateway, iface_name))

    if "httpd" in host.attrs:
        info("*** Starting web server on host %s\n" % mn_host.name)
        mn_host.cmd('nohup python3 ./scripts/webserver.py %s &'
                    % mn_host.name)

    return offload_errors


def warn_offload_errors(offload_errors: dict[str, str]) -> None:
    '''
    Prints a warning about the interfaces whose offloads could not be
    disabled (if any).

    Inputs:
      offload_errors (dict of str to str): the interfaces and their errors
        (see disable_offloads).

    Returns: nothing.
    '''
    if not offload_errors:
        return

    errors = "; ".join(sorted(set(offload_errors.values())))
    warn("*** Warning: Could not disable offloads on {} interfaces ({}): {}\n"
         .format(len(offload_errors), ", ".join(offload_errors), errors))
    warn("*** TCP and UDP traffic through the routers may not work (this is "
         "expected if the\n*** container is running under emulation, e.g., "
         "the arm64 image on an x86_64 computer)\n")


def run(topo_file: str, chirouter_host: str, chirouter_port: int,
        run_cli: bool = True) -> Any:
    '''
    Creates the network specified in a topology file, and connects its
    routers to chirouter.

    Inputs:
      topo_file (str): path to the topology file.
      chirouter_host (str): host where chirouter is running.
      chirouter_port (int): port where chirouter is listening.
      run_cli (bool): whether to run the Mininet CLI.

    Returns:
      (mininet.net.Mininet | None) if run_cli is True, runs the Mininet CLI
      (and stops the network when the CLI exits), and returns None.
      Otherwise, returns the network (the relay is available in its
      chirouter_relay attribute, and must be stopped with stop() before
      stopping the network). Raises OSError if chirouter cannot be reached.
    '''
    setLogLevel('info')

    with open(topo_file, "r") as f:
        topo = Topology.from_json(f)

    net = Mininet(topo=topo.to_mininet_topology(), controller=None)

    offload_errors: dict[str, str] = {}
    for h in topo.hosts:
        offload_errors.update(configure_host(net, h))

    # The relay needs to know the MAC addresses of the routers' interfaces
    # (which are assigned by Mininet)
    for r in topo.routers:
        mn_router = net.get(r.name)
        for intf_name, intf in r.interfaces.items():
            intf.hwaddr = mn_router.intf(r.name + "-" + intf_name).MAC()

    net.start()

    for r in topo.routers:
        offload_errors.update(net.get(r.name).offload_errors)
    warn_offload_errors(offload_errors)

    relay = ChirouterRelay(topo, chirouter_host, chirouter_port)
    try:
        relay.start()
    except OSError:
        # Don't leave the network running if chirouter can't be reached
        net.stop()
        quietRun("pkill -9 -f webserver.py")
        raise
    net.chirouter_relay = relay

    if run_cli:
        CLI(net)
        relay.stop()
        net.stop()

        info("*** Shutting down stale web servers",
             quietRun("pkill -9 -f webserver.py"), "\n")
        return None
    else:
        return net
