# chirouter tests
#
# This module provides ChirouterTestRunner, which the tests use (through the
# chirouter_runner fixture defined in conftest.py) to run chirouter, create
# a simulated network, and run commands (ping, traceroute, etc.) on its hosts.

from typing import Any

import os.path
import random
import shutil
import subprocess
import tempfile
import time

import pytest
from mininet.util import quietRun

import chirouter.simulator as simulator
from chirouter.tests.cmds import (TRACEROUTE_PROBES_PER_HOP, Ping, ARP, WGet,
                                  Traceroute)

# Default port for chirouter
DEFAULT_PORT = 23320

# Range of ports to choose from when using random ports
RANDOM_PORT_MIN = 10000
RANDOM_PORT_MAX = 60000

# How many times to try starting chirouter on a random port
RANDOM_PORT_TRIES = 10

# How long to wait (in seconds) for chirouter to start listening for
# connections after launching it, and how often to check whether it is
# listening
CHIROUTER_START_TIMEOUT = 5
CHIROUTER_START_POLL = 0.01

# Files that list the TCP sockets (IPv4 and IPv6) on Linux, and the
# value of their "st" column for listening sockets
PROC_NET_TCP_FILES = ["/proc/net/tcp", "/proc/net/tcp6"]
TCP_LISTEN = "0A"

# Delay (in milliseconds) between traceroute probes
TRACEROUTE_PROBE_DELAY = 100

# How long traceroute waits (in seconds) for each reply
TRACEROUTE_WAIT = 2

# How long wget waits (in seconds) to connect, or for data to arrive,
# before giving up on a try, and how many times wget tries to download
# a page (wget's defaults allow it to wait for a very long time if the
# router drops the connection's packets). When checking whether a
# connection is refused, wget tries only once.
WGET_TIMEOUT = 5
WGET_TRIES = 3


def is_listening(pid: int, port: int) -> bool:
    '''
    Checks whether a process is listening for TCP connections on a port
    (on any address). We can't check this by connecting to the port, since
    chirouter would take the connection to be the one from Mininet.

    Inputs:
      pid (int): the process ID.
      port (int): the port.

    Returns:
      (bool) True if the process has a listening socket on the port,
      False otherwise (including if another process is listening on it).
    '''
    # Find the inodes of the listening sockets on the port
    inodes = set()
    for proc_file in PROC_NET_TCP_FILES:
        try:
            with open(proc_file) as f:
                lines = f.readlines()[1:]
        except FileNotFoundError:
            continue

        for line in lines:
            # The local address is ADDRESS:PORT (with the port in hex)
            fields = line.split()
            local_port = int(fields[1].split(":")[1], 16)
            if local_port == port and fields[3] == TCP_LISTEN:
                inodes.add(fields[9])

    # Check whether the process has any of those sockets open (the file
    # descriptors of a socket are links to "socket:[INODE]")
    fd_dir = f"/proc/{pid}/fd"
    try:
        fds = os.listdir(fd_dir)
    except FileNotFoundError:
        return False

    for fd in fds:
        try:
            target = os.readlink(os.path.join(fd_dir, fd))
        except FileNotFoundError:
            continue
        if target.startswith("socket:[") and target[8:-1] in inodes:
            return True

    return False


class ChirouterTestRunner:
    '''
    Runs chirouter (unless an external chirouter is used) and the simulated
    network for a single test, and runs commands on the network's hosts.
    '''

    def __init__(self, chirouter_exe: str | None = None,
                 chirouter_host: str = "localhost",
                 chirouter_port: int | None = None, loglevel: int = 0,
                 external_chirouter_port: int | None = None) -> None:
        '''
        Constructor

        Inputs:
          chirouter_exe (str | None): path to the chirouter executable
            (defaults to build/chirouter).
          chirouter_host (str): host where chirouter is running.
          chirouter_port (int | None): port to run chirouter on (-1 to use
            a random port, None to use the default port).
          loglevel (int): log level for chirouter (-1: -q, 0: default,
            1: -v, 2: -vv, 3: -vvv).
          external_chirouter_port (int | None): if not None, don't launch
            chirouter, and instead use the chirouter that is already
            running on this port.

        Raises a RuntimeError if chirouter has to be launched, but the
        executable doesn't exist.
        '''
        if chirouter_exe is None:
            self.chirouter_exe = "build/chirouter"
        else:
            self.chirouter_exe = chirouter_exe

        is_executable = (os.path.isfile(self.chirouter_exe) and
                         os.access(self.chirouter_exe, os.X_OK))
        if external_chirouter_port is None and not is_executable:
            raise RuntimeError("{} does not exist or it is not executable"
                               .format(self.chirouter_exe))

        self.chirouter_port: int | None
        if chirouter_port is None:
            self.chirouter_port = DEFAULT_PORT
            self.randomize_ports = False
        elif chirouter_port == -1:
            self.chirouter_port = None
            self.randomize_ports = True
        else:
            self.chirouter_port = chirouter_port
            self.randomize_ports = False

        self.loglevel = loglevel
        self.chirouter_host = chirouter_host
        self.external_chirouter_port = external_chirouter_port

        self.started = False
        self.mininet_started = False

        # Set when the test starts
        self.port = 0
        self.tmpdir = ""
        self.chirouter_proc: subprocess.Popen[bytes] | None = None
        self.mininet: Any = None

    def _chirouter_cmd(self) -> list[str]:
        '''
        Returns:
          (list of str) the command to run chirouter.
        '''
        cmd = [os.path.abspath(self.chirouter_exe), "-p", str(self.port)]

        if self.loglevel == -1:
            cmd.append("-q")
        elif self.loglevel > 0:
            cmd.append("-" + "v" * self.loglevel)

        return cmd

    def start(self) -> None:
        '''
        Starts the test, launching chirouter (unless an external chirouter
        is used).

        Returns: nothing. Fails the test if chirouter cannot be started.
        '''
        if self.external_chirouter_port is not None:
            self.port = self.external_chirouter_port
            self.started = True
            return

        self.tmpdir = tempfile.mkdtemp()

        if self.randomize_ports:
            tries = RANDOM_PORT_TRIES
        else:
            assert self.chirouter_port is not None
            self.port = self.chirouter_port
            tries = 1

        while tries > 0:
            if self.randomize_ports:
                self.port = random.randint(RANDOM_PORT_MIN, RANDOM_PORT_MAX)

            self.chirouter_proc = subprocess.Popen(self._chirouter_cmd(),
                                                   cwd=self.tmpdir)
            rc = self._wait_for_chirouter()
            if rc is None:
                break

            tries -= 1
            if tries == 0:
                pytest.fail("chirouter process failed to start. rc = %i"
                            % rc)

        self.started = True

    def _wait_for_chirouter(self) -> int | None:
        '''
        Waits until the chirouter process that was just launched is
        listening on self.port, or until it exits (e.g., because the port
        is already in use).

        Returns:
          (int | None) the return code of chirouter if it exited, or None
          if it is listening. Fails the test if chirouter is still not
          listening after CHIROUTER_START_TIMEOUT seconds.
        '''
        assert self.chirouter_proc is not None
        deadline = time.monotonic() + CHIROUTER_START_TIMEOUT

        while time.monotonic() < deadline:
            rc = self.chirouter_proc.poll()
            if rc is not None:
                return rc
            if is_listening(self.chirouter_proc.pid, self.port):
                return None
            time.sleep(CHIROUTER_START_POLL)

        pytest.fail("chirouter did not start listening on port %i after "
                    "%i seconds" % (self.port, CHIROUTER_START_TIMEOUT))

    def start_mininet(self, topo_file: str) -> None:
        '''
        Creates the simulated network, and connects it to chirouter.

        Inputs:
          topo_file (str): name of the topology file (in topologies/).

        Returns: nothing.
        '''
        topo_file = os.path.abspath("topologies/" + topo_file)

        self.mininet = simulator.run(topo_file=topo_file,
                                     chirouter_host=self.chirouter_host,
                                     chirouter_port=self.port,
                                     run_cli=False)

        self.mininet_started = True

    def ping(self, host: str, target: str, count: int = 4,
             ttl: int | None = None, size: int | None = None) -> Ping:
        '''
        Runs ping on a host.

        Inputs:
          host (str): host to run ping on.
          target (str): IP address to ping.
          count (int): number of Echo Requests to send.
          ttl (int | None): TTL of the Echo Requests (None for the default).
          size (int | None): number of data bytes in each Echo Request
            (None for the default).

        Returns:
          (Ping) the output of ping.
        '''
        mn_host = self.mininet.get(host)
        cmd = f"ping -n -c {count} {target}"
        if ttl is not None:
            cmd += f" -t {ttl}"
        if size is not None:
            # Don't allow the datagrams to be fragmented
            cmd += f" -s {size} -M do"
        return Ping(mn_host.cmd(cmd))

    def arp(self, host: str) -> ARP:
        '''
        Gets the contents of a host's ARP cache.

        Inputs:
          host (str): the host.

        Returns:
          (ARP) the host's ARP cache.
        '''
        mn_host = self.mininet.get(host)
        return ARP(mn_host.cmd("ip -j neigh show"))

    def traceroute(self, host: str, target: str, max_hops: int) -> Traceroute:
        '''
        Runs traceroute on a host.

        Inputs:
          host (str): host to run traceroute on.
          target (str): IP address to traceroute.
          max_hops (int): maximum number of hops.

        Returns:
          (Traceroute) the output of traceroute.
        '''
        mn_host = self.mininet.get(host)
        # By default, traceroute only waits for a reply three times longer
        # than the round trip time of earlier replies from the same hop
        # (which can be less than a millisecond), and reports a timeout
        # otherwise. "-w N,0,0" makes it always wait up to N seconds
        # (replies normally take a few milliseconds, but a reply that is
        # never sent costs the full N seconds).
        cmd = (f"traceroute -n -q {TRACEROUTE_PROBES_PER_HOP} "
               f"-z {TRACEROUTE_PROBE_DELAY} -w {TRACEROUTE_WAIT},0,0 "
               f"-m {max_hops} {target}")
        return Traceroute(mn_host.cmd(cmd))

    def wget(self, host: str, target: str, errors: bool = False) -> WGet:
        '''
        Downloads the web page served by a host.

        Inputs:
          host (str): host to run wget on.
          target (str): IP address of the web server.
          errors (bool): if True, include wget's messages in the output
            (e.g., to check whether the connection was refused), and try to
            connect only once. Otherwise, the output only includes the
            downloaded page. In both cases, wget waits at most WGET_TIMEOUT
            seconds for each try.

        Returns:
          (WGet) the output of wget.
        '''
        mn_host = self.mininet.get(host)
        if errors:
            cmd = (f"wget -T {WGET_TIMEOUT} -t 1 -O - "
                   f"http://{target}/ 2>&1")
        else:
            cmd = (f"wget -q -T {WGET_TIMEOUT} -t {WGET_TRIES} -O - "
                   f"http://{target}/")
        return WGet(mn_host.cmd(cmd))

    def end_mininet(self) -> None:
        '''
        Stops the simulated network (if it was started).

        Returns: nothing.
        '''
        if self.mininet_started:
            self.mininet.chirouter_relay.stop()
            self.mininet.stop()
            self.mininet_started = False

            quietRun("pkill -9 -f webserver.py")

    def end(self) -> None:
        '''
        Ends the test, stopping the simulated network and chirouter
        (unless an external chirouter is used).

        Returns: nothing. Fails the test if chirouter exited with an error
        during the test.
        '''
        if not self.started:
            return

        # Stop the network first, so that chirouter sees the relay
        # disconnecting (and so that the network is stopped even if the
        # test fails below)
        self.end_mininet()
        self.started = False

        if self.external_chirouter_port is None:
            assert self.chirouter_proc is not None
            rc = self.chirouter_proc.poll()
            if rc is None:
                self.chirouter_proc.kill()
            self.chirouter_proc.wait()
            shutil.rmtree(self.tmpdir)

            if rc is not None and rc != 0:
                pytest.fail("chirouter process failed during test. rc = %i"
                            % rc)
