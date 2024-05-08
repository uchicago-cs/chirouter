import tempfile
import random
import os.path
import subprocess
import time
import pytest
import shutil

import chirouter.simulator as simulator
from chirouter.tests.cmds import Ping, ARP, WGet, Traceroute

from mininet.node import Ryu
from mininet.util import quietRun


class ChirouterTestRunner:
    '''

    '''


    def __init__(self, chirouter_exe=None, chirouter_host="localhost", chirouter_port=None,
                 loglevel=0, debug=False, external_chirouter_port=None):
        if chirouter_exe is None:
            self.chirouter_exe = "build/chirouter"
        else:
            self.chirouter_exe = chirouter_exe

        if external_chirouter_port is None and not (os.path.exists(self.chirouter_exe) and os.path.isfile(self.chirouter_exe) and os.access(self.chirouter_exe, os.X_OK)):
            raise RuntimeError("{} does not exist or it is not executable".format(self.chirouter_exe))

        if chirouter_port is None:
            self.chirouter_port = 23320
            self.randomize_ports = False
        elif chirouter_port == -1:
            self.chirouter_port = None
            self.randomize_ports = True
        else:
            self.chirouter_port = chirouter_port
            self.randomize_ports = False

        self.loglevel = loglevel
        self.debug = debug
        self.chirouter_host = chirouter_host
        self.external_chirouter_port = external_chirouter_port

        self.started = False
        self.mininet_started = False


    # Start/end test

    def start(self):
        if self.external_chirouter_port is not None:
            self.port = self.external_chirouter_port
            self.started = True
            return

        self.tmpdir = tempfile.mkdtemp()

        if self.randomize_ports:
            self.port = random.randint(10000,60000)
        else:
            self.port = self.chirouter_port

        if self.randomize_ports:
            tries = 10
        else:
            tries = 1


        while tries > 0:

            chirouter_cmd = [os.path.abspath(self.chirouter_exe), "-p", str(self.port)]

            if self.loglevel == 1:
                chirouter_cmd.append("-v")
            elif self.loglevel == 2:
                chirouter_cmd.append("-vv")
            elif self.loglevel == 3:
                chirouter_cmd.append("-vvv")

            self.chirouter_proc = subprocess.Popen(chirouter_cmd, cwd=self.tmpdir)
            time.sleep(0.01)
            rc = self.chirouter_proc.poll()
            if rc is not None:
                tries -=1
                if tries == 0:
                    pytest.fail("chirouter process failed to start. rc = %i" % rc)
                else:
                    if self.randomize_ports:
                        self.port = random.randint(10000,60000)
            else:
                break

        self.started = True

    def start_mininet(self, topo_file):

        topo_file = os.path.abspath("topologies/" + topo_file)

        chirouter_host, chirouter_port = self.chirouter_host, self.port

        command = "PYTHONPATH=src/python/ ryu-manager"

        params  = ["chirouter.controller"]
        params += ["--user-flags src/python/chirouter/ryu_flags.py"]
        params += ["--chirouter-topology-file=" + topo_file]
        params += ["--chirouter-host=" + chirouter_host]
        params += ["--chirouter-port=" + str(chirouter_port)]

        controller = Ryu("c0", command=command, ryuArgs=params)

        self.mininet = simulator.run(topo_file=topo_file, controller=controller, run_cli=False)

        self.mininet_started = True

    def ping(self, host, target, count=4, ttl=None):
        mn_host = self.mininet.get(host)
        cmd = f"ping -n -c {count} {target}"
        if ttl is not None:
            cmd += f" -t {ttl}"
        output = mn_host.cmd(cmd)
        return Ping(output)

    def arp(self, host):
        mn_host = self.mininet.get(host)
        output = mn_host.cmd("arp -n")
        return ARP(output)

    def traceroute(self, host, target, max_hops):
        mn_host = self.mininet.get(host)
        output = mn_host.cmd(f"traceroute -n -z 100 -m {max_hops} {target}")
        return Traceroute(output)

    def wget(self, host, target):
        mn_host = self.mininet.get(host)
        output = mn_host.cmd(f"wget -q -O - http://{target}/")
        return WGet(output)

    def end_mininet(self):
        if self.mininet_started:
            self.mininet.stop()

            quietRun( "pkill -9 -f SimpleHTTPServer" )
            quietRun( "pkill -9 -f webserver.py" )

    def end(self):
        if not self.started:
            return

        if self.external_chirouter_port is None:
            rc = self.chirouter_proc.poll()
            if rc is not None:
                if rc != 0:
                    shutil.rmtree(self.tmpdir)
                    pytest.fail("chirouter process failed during test. rc = %i" % rc)
            else:
                self.chirouter_proc.kill()
            self.chirouter_proc.wait()
            shutil.rmtree(self.tmpdir)

        self.end_mininet()

        self.started = False
