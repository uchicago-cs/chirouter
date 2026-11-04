# Parsers for the output of the commands run by the tests
#
# Each class takes the output of a command (ping, ip neigh, traceroute, wget)
# run on one of the hosts in the simulated network, and provides methods to
# check that the output is the expected one (using assertions, so a failed
# check fails the test). The output of ping and traceroute is parsed with jc
# (https://github.com/kellyjonbrazil/jc), and "ip -j neigh" produces JSON.

import json
from typing import Any

import jc

# Types of ICMP error messages reported by ping (as returned by jc)
PING_NET_UNREACHABLE = "destination_net_unreachable"
PING_HOST_UNREACHABLE = "destination_host_unreachable"
PING_TTL_EXCEEDED = "time_to_live_exceeded"

# Number of probes traceroute sends to each hop (its default)
TRACEROUTE_PROBES_PER_HOP = 3


def parse_with_jc(parser: str, output: str) -> dict[str, Any]:
    '''
    Parses the output of a command with jc.

    Inputs:
      parser (str): the jc parser to use (e.g., "ping").
      output (str): the output of the command.

    Returns:
      (dict) the parsed output (see the jc documentation for each parser).
    '''
    result = jc.parse(parser, output, quiet=True)
    assert isinstance(result, dict)
    return result


class Ping:
    '''
    The output of ping
    '''

    def __init__(self, ping_output: str) -> None:
        '''
        Constructor

        Inputs:
          ping_output (str): the output of ping.
        '''
        self.output = ping_output
        parsed = parse_with_jc("ping", ping_output)
        responses = parsed.get("responses", [])

        # Echo Replies (not including duplicates)
        self.success = [r for r in responses
                        if r["type"] == "reply" and not r.get("duplicate")]
        # Duplicate Echo Replies
        self.duplicates = [r for r in responses
                           if r["type"] == "reply" and r.get("duplicate")]
        # ICMP error messages
        self.fail = [r for r in responses
                     if r["type"] not in ("reply", "timeout",
                                          "unparsable_line")]

        self.transmitted: int | None = parsed.get("packets_transmitted")
        self.received: int | None = parsed.get("packets_received")

    def validate_output_success(self, num_expected: int, expected_source: str,
                                num_expected_exact: bool = True,
                                expected_ttl: int | None = None,
                                min_bytes: int | None = None) -> None:
        '''
        Checks that ping received the expected Echo Replies.

        Inputs:
          num_expected (int): number of Echo Replies expected.
          expected_source (str): IP address the replies must come from.
          num_expected_exact (bool): whether exactly num_expected replies
            must be received (otherwise, at least num_expected replies
            must be received).
          expected_ttl (int | None): TTL the replies must have (used to
            check that each router decrements the TTL), or None to
            accept any TTL.
          min_bytes (int | None): minimum size of the replies (as reported
            by ping), or None to accept replies of any size.

        Returns: nothing (an assertion fails if the output is not correct).
        '''
        assert len(self.success) != 0, \
            f"{expected_source} did not respond to any ICMP Echo Requests" \
            f"\n\n{self.output}"

        assert not self.duplicates, \
            f"Received duplicate Echo Replies from {expected_source} " \
            f"(an IP datagram was probably sent more than once)" \
            f"\n\n{self.output}"

        if num_expected_exact:
            assert len(self.success) == num_expected, \
                f"Expected {num_expected} Echo Replies from " \
                f"{expected_source} but got {len(self.success)} instead" \
                f"\n\n{self.output}"
        else:
            assert len(self.success) >= num_expected, \
                f"Expected at least {num_expected} Echo Replies from " \
                f"{expected_source} but got {len(self.success)} instead" \
                f"\n\n{self.output}"

        for reply in self.success:
            assert reply["response_ip"] == expected_source, \
                f"Expected ICMP message from {expected_source} " \
                f"but got one from {reply['response_ip']} instead" \
                f"\n\n{self.output}"

            if min_bytes is not None:
                assert reply["bytes"] >= min_bytes, \
                    f"Expected Echo Replies with at least {min_bytes} " \
                    f"bytes but got one with {reply['bytes']} bytes (the " \
                    f"reply must include all the data in the Echo Request)" \
                    f"\n\n{self.output}"

            if expected_ttl is not None:
                assert reply["ttl"] == expected_ttl, \
                    f"Expected Echo Replies with TTL {expected_ttl} " \
                    f"but got one with TTL {reply['ttl']} (the TTL must be " \
                    f"decremented by one in each router)\n\n{self.output}"

        # ping prints this if the data in an Echo Reply doesn't match the
        # data in the Echo Request
        assert "wrong data byte" not in self.output, \
            f"The data in an Echo Reply from {expected_source} doesn't " \
            f"match the data in the Echo Request\n\n{self.output}"

    def validate_output_fail(self, num_expected: int, expected_source: str,
                             expected_type: str) -> None:
        '''
        Checks that ping received the expected ICMP error messages.

        Inputs:
          num_expected (int): number of ICMP error messages expected.
          expected_source (str): IP address the messages must come from.
          expected_type (str): the type of error message (one of the
            PING_* constants).

        Returns: nothing (an assertion fails if the output is not correct).
        '''
        assert len(self.fail) != 0, \
            f"{expected_source} did not send any ICMP messages back" \
            f"\n\n{self.output}"

        assert len(self.fail) == num_expected, \
            f"Expected {num_expected} ICMP messages from {expected_source} " \
            f"but got {len(self.fail)} instead\n\n{self.output}"

        for reply in self.fail:
            assert reply["response_ip"] == expected_source, \
                f"Expected ICMP message from {expected_source} " \
                f"but got one from {reply['response_ip']} instead" \
                f"\n\n{self.output}"

            assert reply["type"] == expected_type, \
                f"Expected '{expected_type}' ICMP message " \
                f"but got '{reply['type']}' instead\n\n{self.output}"


class ARP:
    '''
    The contents of a host's ARP cache (the output of "ip -j neigh show")
    '''

    def __init__(self, ip_neigh_output: str) -> None:
        '''
        Constructor

        Inputs:
          ip_neigh_output (str): the output of "ip -j neigh show".
        '''
        # MAC addresses (or None, if the entry is incomplete or failed),
        # indexed by IP address
        self.mappings: dict[str, str | None] = {}

        for entry in json.loads(ip_neigh_output or "[]"):
            self.mappings[entry["dst"]] = entry.get("lladdr")


class Traceroute:
    '''
    The output of traceroute
    '''

    def __init__(self, traceroute_output: str) -> None:
        '''
        Constructor

        Inputs:
          traceroute_output (str): the output of traceroute (run with
            TRACEROUTE_PROBES_PER_HOP probes per hop).
        '''
        self.output = traceroute_output
        self.hops: list[dict[str, Any]] = parse_with_jc(
            "traceroute", traceroute_output).get("hops", [])

    def validate_output(self, expected_hops: list[str],
                        max_timeouts: int = 0) -> None:
        '''
        Checks that traceroute found the expected hops.

        Inputs:
          expected_hops (list of str): IP address of each hop.
          max_timeouts (int): maximum number of probes (in each hop)
            that can time out.

        Returns: nothing (an assertion fails if the output is not correct).
        '''
        assert len(self.hops) == len(expected_hops), \
            f"Expected {len(expected_hops)} traceroute hops " \
            f"but got {len(self.hops)} instead\n\n{self.output}"

        for hop, expected_hop in zip(self.hops, expected_hops):
            num = hop["hop"]
            probes = hop["probes"]
            hosts = {p["ip"] for p in probes}

            # jc doesn't include the probes that timed out
            num_timeouts = TRACEROUTE_PROBES_PER_HOP - len(probes)
            assert num_timeouts <= max_timeouts, \
                f"Hop #{num} has too many timeouts\n\n{self.output}"

            assert len(hosts) == 1, \
                f"Hop #{num} includes replies from multiple hosts " \
                f"(or no replies at all)\n\n{self.output}"
            host = hosts.pop()
            assert host == expected_hop, \
                f"Expected hop #{num} to be {expected_hop} " \
                f"but got {host} instead\n\n{self.output}"

            errors = [p["annotation"] for p in probes if p.get("annotation")]
            assert not errors, \
                f"Hop #{num} includes errors: {' '.join(errors)}" \
                f"\n\n{self.output}"


class WGet:
    '''
    The output of wget (when downloading the page served by
    scripts/webserver.py)
    '''

    EXPECTED_WGET_OUTPUT = """<html>
<head><title> This is {server}</title></head>
<body>
Congratulations! <br/>
Your router successfully routes your packets to and from {server}.<br/>
</body>
</html>"""

    def __init__(self, wget_output: str) -> None:
        '''
        Constructor

        Inputs:
          wget_output (str): the output of wget.
        '''
        self.wget_output = wget_output.replace("\r\n", "\n")

    def validate_output(self, server: str) -> None:
        '''
        Checks that wget downloaded the expected page.

        Inputs:
          server (str): name of the host running the web server.

        Returns: nothing (an assertion fails if the output is not correct).
        '''
        expected = WGet.EXPECTED_WGET_OUTPUT.format(server=server)
        assert self.wget_output == expected, \
            f"Got unexpected wget output from {server}\n\n{self.wget_output}"

    def validate_connection_refused(self, target: str) -> None:
        '''
        Checks that wget could not connect because the connection was
        refused (e.g., because of an ICMP Port Unreachable message). The
        output must include wget's messages (see ChirouterTestRunner.wget).

        Inputs:
          target (str): IP address wget tried to connect to.

        Returns: nothing (an assertion fails if the output is not correct).
        '''
        assert "Connection refused" in self.wget_output, \
            f"Expected the connection to {target} to be refused (because of " \
            f"an ICMP Port Unreachable message)\n\n{self.wget_output}"
