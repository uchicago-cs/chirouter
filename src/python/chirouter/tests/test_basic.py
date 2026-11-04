# Tests for the basic topology (a single router connecting three networks)
#
# These tests follow the order suggested in the chirouter documentation
# (responding to ARP requests, ICMP messages directed to the router,
# sending ARP requests, IP forwarding, etc.)

import pytest

from chirouter.tests import ChirouterTestRunner
from chirouter.tests.cmds import (PING_HOST_UNREACHABLE, PING_NET_UNREACHABLE,
                                  PING_TTL_EXCEEDED)

# An IP address in client1's network that is not assigned to any host
UNUSED_IP = "10.0.0.99"

# Number of data bytes in "large" Echo Requests (the largest that fit in a
# 1500-byte IP datagram, the largest that fits in an Ethernet frame)
LARGE_PING_SIZE = 1472

# Size of the replies to "large" Echo Requests, as reported by ping
# (the ICMP header plus the data)
LARGE_PING_REPLY_SIZE = LARGE_PING_SIZE + 8


class TestARP:
    '''
    Tests for ARP
    '''

    @pytest.mark.category("RESPONDING_ARP_REQUESTS")
    def test_arp_request(self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router responds to ARP requests on one of its
        interfaces.

        Equivalent to running:

            mininet> client1 ping -c 1 10.0.0.1
            mininet> client1 arp -n

        And checking whether client1's ARP cache shows a mapping between
        10.0.0.1 and the router's MAC address for eth3.
        '''
        chirouter_runner.start_mininet("basic.json")
        mn = chirouter_runner.mininet

        chirouter_runner.ping("client1", "10.0.0.1", count=1)
        arp = chirouter_runner.arp("client1")

        expected_mac = mn["r1"].nameToIntf["r1-eth3"].mac
        actual_mac = arp.mappings.get("10.0.0.1")

        error_msg = (f"Expected client1's ARP cache to map 10.0.0.1 "
                     f"to {expected_mac}, ")
        if actual_mac is None:
            error_msg += "but there is no mapping at all for 10.0.0.1."
        else:
            error_msg += f"but it instead maps to {actual_mac}"

        assert expected_mac == actual_mac, error_msg

    @pytest.mark.category("RESPONDING_ARP_REQUESTS")
    def test_arp_request_other_ip(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router replies to ARP requests for its own IP
        address, but not to ARP requests for other IP addresses.

        Equivalent to running:

            mininet> client1 ping -c 1 10.0.0.1
            mininet> client1 ping -c 1 10.0.0.99
            mininet> client1 arp -n

        Where 10.0.0.99 is an IP address in client1's network that is not
        assigned to any host (so client1 will send an ARP request for it),
        and checking that client1's ARP cache has the router's MAC address
        for 10.0.0.1, but no MAC address for 10.0.0.99:

            Address                  HWtype  HWaddress           Flags Mask
            10.0.0.1                 ether   e2:37:3d:e5:c5:29   C
            10.0.0.99                        (incomplete)
        '''
        chirouter_runner.start_mininet("basic.json")
        mn = chirouter_runner.mininet

        chirouter_runner.ping("client1", "10.0.0.1", count=1)
        chirouter_runner.ping("client1", UNUSED_IP, count=1)
        arp = chirouter_runner.arp("client1")

        router_mac = mn["r1"].nameToIntf["r1-eth3"].mac

        # A router that doesn't reply to any ARP requests would trivially
        # pass the check below, so we also check that it replies to ARP
        # requests for its own IP address.
        assert arp.mappings.get("10.0.0.1") == router_mac, \
            f"Expected client1's ARP cache to map 10.0.0.1 to {router_mac}, " \
            f"but it maps it to {arp.mappings.get('10.0.0.1')}"

        actual_mac = arp.mappings.get(UNUSED_IP)

        assert actual_mac is None, \
            f"Expected client1's ARP cache to have no MAC address for " \
            f"{UNUSED_IP} (which is not assigned to any host), but it maps " \
            f"it to {actual_mac}" + \
            (" (the router's MAC address)" if actual_mac == router_mac else "")


class TestICMP:
    '''
    Tests that use ping
    '''

    @pytest.mark.category("ICMP_ROUTER")
    def test_ping_router(self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router responds to ICMP Echo Requests.

        Equivalent to running this:

            mininet> client1 ping -c 4 10.0.0.1

        And expecting four successful replies:

            PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
            84 bytes from 10.0.0.1: icmp_seq=1 ttl=255 time=22.3 ms
            84 bytes from 10.0.0.1: icmp_seq=2 ttl=255 time=3.19 ms
            84 bytes from 10.0.0.1: icmp_seq=3 ttl=255 time=20.5 ms
            84 bytes from 10.0.0.1: icmp_seq=4 ttl=255 time=38.3 ms

            --- 10.0.0.1 ping statistics ---
            4 packets transmitted, 4 received, 0% packet loss, time 3003ms
            rtt min/avg/max/mdev = 3.197/21.120/38.381/12.460 ms
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "10.0.0.1", count=4)

        ping.validate_output_success(num_expected=4, expected_source="10.0.0.1")

    @pytest.mark.category("ICMP_ROUTER")
    def test_router_host_unreachable_router_interface(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router produces an ICMP Host Unreachable reply if it
        receives an IP datagram directed to one of its IP addresses, but
        where the destination IP address is not the IP address of the
        interface on which the datagram was received.

        Equivalent to running this:

            mininet> client1 ping -c 4 192.168.1.1

        And receiving four Host Unreachable messages:

            PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
            From 10.0.0.1 icmp_seq=1 Destination Host Unreachable
            From 10.0.0.1 icmp_seq=2 Destination Host Unreachable
            From 10.0.0.1 icmp_seq=3 Destination Host Unreachable
            From 10.0.0.1 icmp_seq=4 Destination Host Unreachable

            --- 192.168.1.1 ping statistics ---
            4 packets transmitted, 0 received, +4 errors, 100% packet loss, time 3005ms
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "192.168.1.1", count=4)

        ping.validate_output_fail(
            num_expected=4, expected_source="10.0.0.1",
            expected_type=PING_HOST_UNREACHABLE)

    @pytest.mark.category("ICMP_ROUTER")
    def test_router_time_exceeded(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router sends an ICMP Time Exceeded message if it
        receives an IP datagram with a TTL set to 1.

        Equivalent to running this:

            mininet> client1 ping -c 4 -t 1 10.0.0.1

        And expecting to see four Time Exceeded messages:

            PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
            From 10.0.0.1 icmp_seq=1 Time to live exceeded
            From 10.0.0.1 icmp_seq=2 Time to live exceeded
            From 10.0.0.1 icmp_seq=3 Time to live exceeded
            From 10.0.0.1 icmp_seq=4 Time to live exceeded

            --- 10.0.0.1 ping statistics ---
            4 packets transmitted, 0 received, +4 errors, 100% packet loss, time 3005ms
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "10.0.0.1", count=4, ttl=1)

        ping.validate_output_fail(num_expected=4, expected_source="10.0.0.1",
                                  expected_type=PING_TTL_EXCEEDED)

    @pytest.mark.category("ICMP_ROUTER")
    def test_ping_router_large(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router responds to ICMP Echo Requests that are as
        large as an Ethernet frame allows (1500-byte IP datagrams), and that
        the Echo Replies contain the same data as the Echo Requests.

        Equivalent to running this:

            mininet> client1 ping -c 4 -s 1472 10.0.0.1

        And expecting four successful replies:

            PING 10.0.0.1 (10.0.0.1) 1472(1500) bytes of data.
            1480 bytes from 10.0.0.1: icmp_seq=1 ttl=255 time=0.412 ms
            1480 bytes from 10.0.0.1: icmp_seq=2 ttl=255 time=0.385 ms
            1480 bytes from 10.0.0.1: icmp_seq=3 ttl=255 time=0.371 ms
            1480 bytes from 10.0.0.1: icmp_seq=4 ttl=255 time=0.402 ms
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "10.0.0.1", count=4,
                                     size=LARGE_PING_SIZE)

        ping.validate_output_success(num_expected=4, expected_source="10.0.0.1",
                                     min_bytes=LARGE_PING_REPLY_SIZE)

    @pytest.mark.category("ICMP_ROUTER")
    def test_router_port_unreachable_tcp(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router produces a Port Unreachable message if it
        receives a TCP segment directed to one of its IP addresses (see
        also test_traceroute_router, which checks this for UDP).

        Equivalent to running this:

            mininet> client1 wget -O - http://10.0.0.1/

        And seeing that the connection is refused immediately:

            Connecting to 10.0.0.1:80... failed: Connection refused.

        (if the router doesn't send a Port Unreachable message, the
        connection will instead time out)
        '''
        chirouter_runner.start_mininet("basic.json")

        wget = chirouter_runner.wget("client1", "10.0.0.1", errors=True)

        wget.validate_connection_refused("10.0.0.1")

    @pytest.mark.category("ARP_SENDING_REQ_AND_PROCESS_REPLY")
    def test_arp_replies(self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that router can send ARP requests and will process ARP replies.
        This test will pass before the router can process pending ARP replies
        (i.e., keeping a list of withheld frames that are sent once the ARP
        reply is sent). It will also pass before IP forwarding is implemented,
        if you assume that you only ever forward IP datagrams to server1.

        Equivalent to running this:

            mininet> client1 ping -c 4 server1

        But only receiving some of the ping replies:

            PING 192.168.1.2 (192.168.1.2) 56(84) bytes of data.
            64 bytes from 192.168.1.2: icmp_seq=3 ttl=63 time=18.7 ms
            64 bytes from 192.168.1.2: icmp_seq=4 ttl=63 time=49.0 ms

            --- 192.168.1.2 ping statistics ---
            4 packets transmitted, 2 received, 50% packet loss, time 3019ms
            rtt min/avg/max/mdev = 18.739/33.883/49.028/15.145 ms

        This happens because the first ICMP messages will be lost (because we’re
        not storing them in the withheld frames list of a pending ARP request)
        but, as soon as we receive an ARP reply and add the MAC address to the
        ARP cache, the router is able to deliver those IP datagrams.
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "192.168.1.2", count=4)

        ping.validate_output_success(num_expected=1,
                                     expected_source="192.168.1.2",
                                     num_expected_exact=False,
                                     expected_ttl=63)

    @pytest.mark.category("IP_FORWARDING_BASIC")
    def test_ping_server2_basic(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that router can forward datagrams correctly. Like test
        test_arp_replies, this test will pass before the router can process
        pending ARP replies (i.e., keeping a list of withheld frames that are
        sent once the ARP reply is sent). It will also pass before IP
        forwarding is implemented, if you assume that you only ever
        forward IP datagrams to server1.

        Equivalent to running this:

            mininet> client1 ping -c 4 server2

        But only receiving some of the ping replies:

            PING 172.16.0.2 (172.16.0.2) 56(84) bytes of data.
            64 bytes from 172.16.0.2: icmp_seq=3 ttl=63 time=18.7 ms
            64 bytes from 172.16.0.2: icmp_seq=4 ttl=63 time=49.0 ms

            --- 172.16.0.2 ping statistics ---
            4 packets transmitted, 2 received, 50% packet loss, time 3019ms
            rtt min/avg/max/mdev = 18.739/33.883/49.028/15.145 ms

        This happens because the first ICMP messages will be lost (because we’re
        not storing them in the withheld frames list of a pending ARP request)
        but, as soon as we receive an ARP reply and add the MAC address to the
        ARP cache, the router is able to deliver those IP datagrams.
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "172.16.0.2", count=4)

        ping.validate_output_success(num_expected=1,
                                     expected_source="172.16.0.2",
                                     num_expected_exact=False,
                                     expected_ttl=63)

    @pytest.mark.category("IP_FORWARDING_BASIC")
    def test_router_network_unreachable(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router will send an ICMP Network Unreachable message if
        it receives an IP datagram that it cannot forward.

        Equivalent to running this:

            mininet> client1 ping -c 4 8.8.8.8

        And expecting four Network Unreachable messages:

            PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
            From 10.0.0.1 icmp_seq=1 Destination Net Unreachable
            From 10.0.0.1 icmp_seq=2 Destination Net Unreachable
            From 10.0.0.1 icmp_seq=3 Destination Net Unreachable
            From 10.0.0.1 icmp_seq=4 Destination Net Unreachable

            --- 8.8.8.8 ping statistics ---
            4 packets transmitted, 0 received, +4 errors, 100% packet loss, time 3004ms
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "8.8.8.8", count=4)

        ping.validate_output_fail(num_expected=4, expected_source="10.0.0.1",
                                  expected_type=PING_NET_UNREACHABLE)

    @pytest.mark.category("IP_FORWARDING_BASIC")
    def test_router_network_unreachable_ttl1(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router sends an ICMP Network Unreachable message
        (and not an ICMP Time Exceeded message) if it receives an IP
        datagram with a TTL of 1 that it cannot forward.

        Equivalent to running this:

            mininet> client1 ping -c 4 -t 1 8.8.8.8

        And expecting four Network Unreachable messages:

            PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
            From 10.0.0.1 icmp_seq=1 Destination Net Unreachable
            From 10.0.0.1 icmp_seq=2 Destination Net Unreachable
            From 10.0.0.1 icmp_seq=3 Destination Net Unreachable
            From 10.0.0.1 icmp_seq=4 Destination Net Unreachable
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "8.8.8.8", count=4, ttl=1)

        ping.validate_output_fail(num_expected=4, expected_source="10.0.0.1",
                                  expected_type=PING_NET_UNREACHABLE)

    @pytest.mark.category("PENDING_ARP_REQUESTS")
    def test_ping_server1(self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router correctly handles pending ARP requests, meaning
        it keeps track of the frames that are waiting on an ARP reply to
        be delivered (instead of being discarded because the ARP cache doesn't
        have an entry for the destination IP). This test will pass if
        IP forwarding is not implemented, and you assume that you only ever
        forward to server1.

        Equivalent to running this:

            mininet> client1 ping -c 4 server1

        And receiving all four ping replies:

            PING 192.168.1.2 (192.168.1.2) 56(84) bytes of data.
            64 bytes from 192.168.1.2: icmp_seq=1 ttl=63 time=21.7 ms
            64 bytes from 192.168.1.2: icmp_seq=2 ttl=63 time=48.2 ms
            64 bytes from 192.168.1.2: icmp_seq=3 ttl=63 time=29.2 ms
            64 bytes from 192.168.1.2: icmp_seq=4 ttl=63 time=10.3 ms

            --- 192.168.1.2 ping statistics ---
            4 packets transmitted, 4 received, 0% packet loss, time 3005ms
            rtt min/avg/max/mdev = 10.353/27.408/48.246/13.791 ms
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "192.168.1.2", count=4)

        ping.validate_output_success(num_expected=4,
                                     expected_source="192.168.1.2",
                                     expected_ttl=63)

    @pytest.mark.category("BASIC_TOPOLOGY")
    def test_ping_server2(self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks end-to-end functionality of the basic topology by pinging
        server2 from client1. Requires the router to handle pending ARP
        requests (so that no Echo Requests are lost).

        Equivalent to running this:

            mininet> client1 ping -c 4 server2

        And receiving all four ping replies:

            PING 172.16.0.2 (172.16.0.2) 56(84) bytes of data.
            64 bytes from 172.16.0.2: icmp_seq=1 ttl=63 time=55.3 ms
            64 bytes from 172.16.0.2: icmp_seq=2 ttl=63 time=33.8 ms
            64 bytes from 172.16.0.2: icmp_seq=3 ttl=63 time=19.5 ms
            64 bytes from 172.16.0.2: icmp_seq=4 ttl=63 time=49.6 ms
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "172.16.0.2", count=4)

        ping.validate_output_success(num_expected=4,
                                     expected_source="172.16.0.2",
                                     expected_ttl=63)

    @pytest.mark.category("BASIC_TOPOLOGY")
    def test_ping_server2_large(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router can forward IP datagrams that are as large
        as an Ethernet frame allows (1500-byte IP datagrams).

        Equivalent to running this:

            mininet> client1 ping -c 4 -s 1472 server2

        And receiving all four ping replies:

            PING 172.16.0.2 (172.16.0.2) 1472(1500) bytes of data.
            1480 bytes from 172.16.0.2: icmp_seq=1 ttl=63 time=1.02 ms
            1480 bytes from 172.16.0.2: icmp_seq=2 ttl=63 time=0.617 ms
            1480 bytes from 172.16.0.2: icmp_seq=3 ttl=63 time=0.598 ms
            1480 bytes from 172.16.0.2: icmp_seq=4 ttl=63 time=0.633 ms
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "172.16.0.2", count=4,
                                     size=LARGE_PING_SIZE)

        ping.validate_output_success(num_expected=4,
                                     expected_source="172.16.0.2",
                                     expected_ttl=63,
                                     min_bytes=LARGE_PING_REPLY_SIZE)

    @pytest.mark.category("TIMING_OUT_PENDING_ARP_REQUESTS")
    def test_router_host_unreachable(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router produces a Host Unreachable message if an ARP
        request times out (because it requested the MAC address of a host that
        does not exist).

        Equivalent to running:

            mininet> client1 ping -c 4 192.168.1.3

        And expecting four Host Unreachable messages:

            PING 192.168.1.3 (192.168.1.3) 56(84) bytes of data.
            From 10.0.0.1 icmp_seq=1 Destination Host Unreachable
            From 10.0.0.1 icmp_seq=2 Destination Host Unreachable
            From 10.0.0.1 icmp_seq=3 Destination Host Unreachable
            From 10.0.0.1 icmp_seq=4 Destination Host Unreachable

            --- 192.168.1.3 ping statistics ---
            4 packets transmitted, 0 received, +4 errors, 100% packet loss, time 2999ms
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "192.168.1.3", count=4)

        ping.validate_output_fail(
            num_expected=4, expected_source="10.0.0.1",
            expected_type=PING_HOST_UNREACHABLE)

    @pytest.mark.category("TIMING_OUT_PENDING_ARP_REQUESTS")
    def test_router_host_unreachable_ttl1(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router sends an ICMP Host Unreachable message (and
        not an ICMP Time Exceeded message) if it receives an IP datagram
        with a TTL of 1 for a host that does not reply to ARP requests.

        Equivalent to running this:

            mininet> client1 ping -c 4 -t 1 192.168.1.3

        And expecting four Host Unreachable messages:

            PING 192.168.1.3 (192.168.1.3) 56(84) bytes of data.
            From 10.0.0.1 icmp_seq=1 Destination Host Unreachable
            From 10.0.0.1 icmp_seq=2 Destination Host Unreachable
            From 10.0.0.1 icmp_seq=3 Destination Host Unreachable
            From 10.0.0.1 icmp_seq=4 Destination Host Unreachable
        '''
        chirouter_runner.start_mininet("basic.json")

        ping = chirouter_runner.ping("client1", "192.168.1.3", count=4,
                                     ttl=1)

        ping.validate_output_fail(
            num_expected=4, expected_source="10.0.0.1",
            expected_type=PING_HOST_UNREACHABLE)


class TestTraceroute:
    '''
    Tests that use traceroute
    '''
    @pytest.mark.category("ICMP_ROUTER")
    def test_traceroute_router(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks that the router produces a Port Unreachable message if it
        receives a TCP/UDP directed to any of its IP addresses.

        Equivalent to running:

            mininet> client1 traceroute 10.0.0.1

        And expecting to see a single hop at 10.0.0.1:

            traceroute to 10.0.0.1 (10.0.0.1), 30 hops max, 60 byte packets
             1  10.0.0.1 (10.0.0.1)  17.487 ms  17.826 ms  17.825 ms

        Traceroute depends on sending TCP/UDP messages to intermediate routers
        that will generate a Port Unreachable message, so a working traceroute
        is a sign that Port Unreachable is correctly implemented.
        '''
        chirouter_runner.start_mininet("basic.json")

        traceroute = chirouter_runner.traceroute("client1", "10.0.0.1",
                                                 max_hops=5)

        expected_hops = ["10.0.0.1"]
        traceroute.validate_output(expected_hops=expected_hops)

    @pytest.mark.category("BASIC_TOPOLOGY")
    def test_traceroute_server1(
            self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks end-to-end functionality of the basic topology by doing
        a traceroute from client1 to server1. Requires that
        most/all router functionality be implemented.

        Equivalent to running this:

            mininet> client1 traceroute -n server1

        And seeing the following:

            traceroute to 192.168.1.2 (192.168.1.2), 30 hops max, 60 byte packets
             1  10.0.0.1 (10.0.0.1)  105.121 ms  108.790 ms  172.695 ms
             2  192.168.1.2 (192.168.1.2)  242.927 ms  306.856 ms  306.985 ms
        '''
        chirouter_runner.start_mininet("basic.json")

        traceroute = chirouter_runner.traceroute("client1", "192.168.1.2",
                                                 max_hops=5)

        traceroute.validate_output(expected_hops=["10.0.0.1", "192.168.1.2"],
                                   max_timeouts=2)


class TestWget:
    '''
    Tests that download a web page with wget
    '''

    @pytest.mark.category("BASIC_TOPOLOGY")
    def test_wget_server1(self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks end-to-end functionality of the basic topology by downloading
        a small file from the web server running in server1. Requires that
        most/all router functionality be implemented.

        Equivalent to running this:

            mininet> client1 wget -q -O - http://192.168.1.2/

        And seeing the following:

            <html>
            <head><title> This is server1</title></head>
            <body>
            Congratulations! <br/>
            Your router successfully routes your packets to and from server1.<br/>
            </body>
            </html>
        '''
        chirouter_runner.start_mininet("basic.json")

        wget = chirouter_runner.wget("client1", "192.168.1.2")

        wget.validate_output("server1")

    @pytest.mark.category("BASIC_TOPOLOGY")
    def test_wget_server2(self, chirouter_runner: ChirouterTestRunner) -> None:
        '''
        Checks end-to-end functionality of the basic topology by downloading
        a small file from the web server running in server2. Requires that
        most/all router functionality be implemented.

        Equivalent to running this:

            mininet> client1 wget -q -O - http://172.16.0.2/

        And seeing the following:

            <html>
            <head><title> This is server2</title></head>
            <body>
            Congratulations! <br/>
            Your router successfully routes your packets to and from server2.<br/>
            </body>
            </html>
        '''
        chirouter_runner.start_mininet("basic.json")

        wget = chirouter_runner.wget("client1", "172.16.0.2")

        wget.validate_output("server2")
