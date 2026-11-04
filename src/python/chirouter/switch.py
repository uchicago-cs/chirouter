# The switches in the simulated network
#
# Each switch is a Linux bridge (with STP off) in the container's root
# namespace. Mininet's LinuxBridge does the same, but it configures the
# bridge with brctl, which is deprecated and uses ioctls that are not
# supported when the image is run under emulation (e.g., an arm64 image
# on an x86-64 machine), so we use iproute2 instead.

from typing import Any

from mininet.node import Switch


class BridgeSwitch(Switch):
    '''
    A switch, implemented with a Linux bridge. To see the interfaces that
    are connected to a switch, run "bridge link" in the Docker container.
    '''

    def start(self, controllers: list[Any]) -> None:
        '''
        Creates the bridge, and adds the switch's interfaces to it (called
        by Mininet when the network is started).

        Inputs:
          controllers (list): OpenFlow controllers (ignored).

        Returns: nothing.
        '''
        # In case a bridge with the same name was left behind by an
        # earlier run
        self.cmd("ip link del", self, "2> /dev/null")

        self.cmd("ip link add name", self, "type bridge stp_state 0")
        for intf in self.intfList():
            if self.name in intf.name:
                self.cmd("ip link set", intf, "master", self)
        self.cmd("ip link set", self, "up")

    def stop(self, deleteIntfs: bool = True) -> None:
        '''
        Deletes the bridge (called by Mininet when the network is stopped).

        Inputs:
          deleteIntfs (bool): whether to also delete the switch's
            interfaces.

        Returns: nothing.
        '''
        self.cmd("ip link del", self)
        super().stop(deleteIntfs)

    def connected(self) -> bool:
        '''
        Returns:
          (bool) whether the switch is ready (always True, since the switch
          doesn't need to connect to an OpenFlow controller).
        '''
        return True
