import re

class SuccessfulPingLine:

    RE = re.compile(r"(?P<bytes>[0-9]+) bytes from (?P<host>[0-9\.]+): icmp_seq=(?P<icmp_seq>[0-9]+) ttl=(?P<ttl>[0-9]+) time=(?P<time>[0-9\.]+) ms")

    def __init__(self, line):
        m = SuccessfulPingLine.RE.match(line)
        if m is None:
            raise ValueError(f"Could not parse as a successful ping: {line}")

        self.bytes = int(m.group("bytes"))
        self.host = m.group("host")
        self.icmp_seq = int(m.group("icmp_seq"))
        self.ttl = int(m.group("ttl"))
        self.time = float(m.group("time"))

    def __str__(self):
        return f"{self.bytes} bytes from {self.host}: icmp_seq={self.icmp_seq} ttl={self.ttl} time={self.time}"


class FailedPingLine:

    RE = re.compile(r"From (?P<error_source>[0-9\.]+) icmp_seq=(?P<icmp_seq>[0-9]+) (?P<reason>.*)")

    def __init__(self, line):
        m = FailedPingLine.RE.match(line)
        if m is None:
            raise ValueError(f"Could not parse as a failed ping: {line}")

        self.error_source = m.group("error_source")
        self.icmp_seq = int(m.group("icmp_seq"))
        self.reason = m.group("reason").strip()

    def __str__(self):
        return f"From {self.error_source} icmp_seq={self.icmp_seq} {self.reason}"


class StatsLine:

    RE = re.compile(r"(?P<transmitted>[0-9]+) packets transmitted, (?P<received>[0-9]+) received, (?P<packet_loss_pct>[0-9\.]+)% packet loss, time (?P<time>[0-9\.]+)ms")

    def __init__(self, line):
        m = StatsLine.RE.match(line)
        if m is None:
            raise ValueError(f"Could not parse as a stats line: {line}")

        self.transmitted = int(m.group("transmitted"))
        self.received = int(m.group("received"))
        self.packet_loss_pct = float(m.group("packet_loss_pct"))
        self.time = float(m.group("time"))

    def __str__(self):
        return f"{transmitted} packets transmitted, {received} received, {packet_loss_pct}% packet loss, time {time}ms"


class Ping:

    def __init__(self, ping_output):
        self.output = ping_output
        self.success = []
        self.fail = []
        self.transmitted = None
        self.received = None
        lines = ping_output.split("\n")
        for line in lines:
            try:
                sp = SuccessfulPingLine(line)
                self.success.append(sp)
                continue
            except ValueError:
                pass

            try:
                sp = FailedPingLine(line)
                self.fail.append(sp)
                continue
            except ValueError:
                pass

            try:
                stats = StatsLine(line)
                self.transmitted = stats.transmitted
                self.received = stats.received
                continue
            except ValueError:
                pass

    def validate_output_success(self, num_expected, expected_source, num_expected_exact=True):

        assert len(self.success) != 0, \
            f"{expected_source} did not respond to any ICMP Echo Requests\n\n{self.output}"

        if num_expected_exact:
            assert len(self.success) == num_expected, \
                f"Expected {num_expected} Echo Replies from {expected_source} " \
                f"but got {len(self.success)} instead\n\n{self.output}"
        else:
            assert len(self.success) >= num_expected, \
                f"Expected at least {num_expected} Echo Replies from {expected_source} " \
                f"but got {len(self.success)} instead\n\n{self.output}"

        for reply in self.success:
            assert reply.host == expected_source, \
                f"Expected ICMP message from {expected_source} " \
                f"but got one from {reply.host} instead\n\n{self.output}"

    def validate_output_fail(self, num_expected, expected_source, expected_reason):

        assert len(self.fail) != 0, \
            f"{expected_source} did not send any ICMP messages back\n\n{self.output}"

        assert len(self.fail) == num_expected, \
            f"Expected {num_expected} ICMP messages from {expected_source} " \
            f"but got {len(self.fail)} instead\n\n{self.output}"

        for reply in self.fail:
            assert reply.error_source == expected_source, \
                f"Expected ICMP message from {expected_source} " \
                f"but got one from {reply.error_source} instead\n\n{self.output}"

            assert reply.reason == expected_reason, \
                f"Expected '{expected_reason}' ICMP message " \
                f"but got '{reply.reason} instead\n\n{self.output}"


class ARPMappingLine:

    def __init__(self, line):
        self.ip_address = line[0:25].strip()
        self.hw_type = line[25:33].strip()
        self._hw_address = line[33:53].strip()
        self.flags = line[53:59].strip()
        self.mask = line[59:75].strip()
        self.iface = line[75:].strip()

    @property
    def hw_address(self):
        if self._hw_address == "(incomplete)" or len(self._hw_address) == 0 or self._hw_address is None:
            return None
        else:
            return self._hw_address

    def __str__(self):
        return f"{self.ip_address} {self.hw_type} {self.hw_address} {self.flags} {self.mask} {self.iface}"

class ARP:

    def __init__(self, arp_output):
        self.mappings = {}

        lines = arp_output.split("\n")
        lines.pop(0)
        for line in lines:
            if len(line.strip()) != 0:
                arp_map = ARPMappingLine(line)
                self.mappings[arp_map.ip_address] = arp_map.hw_address


class TracerouteHop:

    def __init__(self, line):
        self.num = line.strip().split()[0]
        self.times = re.findall(r"[0-9.]+ ms", line)
        self.hosts = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
        self.errors = re.findall(r"!.", line)
        self.num_timeouts = len(re.findall(r"\*", line))


class Traceroute:

    def __init__(self, traceroute_output):
        self.output = traceroute_output
        self.hops = []

        lines = traceroute_output.split("\n")
        for line in lines:
            if len(line.strip()) != 0:
                hop = TracerouteHop(line)
                if hop.num.isnumeric():
                    self.hops.append(hop)

    def validate_output(self, expected_hops, max_timeouts=0):
        assert len(self.hops) == len(expected_hops), \
            f"Expected {len(expected_hops)} traceroute hops " \
            f"but got {len(self.hops)} instead\n\n{self.output}"

        for i, (hop, expected_hop) in enumerate(zip(self.hops, expected_hops)):
            assert len(hop.hosts) == 1, \
                f"Hop #{hop.num} includes replies from multiple hosts\n\n{self.output}"
            host = hop.hosts[0]
            assert host == expected_hop, \
                f"Expected hop #{i+1} to be {expected_hop} " \
                f"but got {host} instead\n\n{self.output}"

            assert hop.num_timeouts <= max_timeouts, \
                f"Hop #{hop.num} has too many timeouts\n\n{self.output}"

            assert len(hop.errors) == 0, \
                f"Hop #{hop.num} includes errors: {' '.join(hop.errors)}\n\n{self.output}"

class WGet:

    EXPECTED_WGET_OUTPUT="""<html>
<head><title> This is {server}</title></head>
<body>
Congratulations! <br/>
Your router successfully routes your packets to and from {server}.<br/>
</body>
</html>"""

    def __init__(self, wget_output):
        self.wget_output = wget_output.replace("\r\n", "\n")

    def validate_output(self, server):
        assert self.wget_output == WGet.EXPECTED_WGET_OUTPUT.format(server=server), \
            f"Got unexpected wget output from {server}\n\n{self.wget_output}"