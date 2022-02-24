import pytest


class TestICMP(object):

    @pytest.mark.category("3ROUTER")
    def test_longest_prefix_match(self, chirouter_runner):
        """
        Tests end-to-end functionality of the three-router topology by pinging
        host100 from host1. Requires most/all router functionality to be
        implemented. This particular test should only work if Longest Prefix
        Match is correctly implemented.

        Equivalent to running this:

            mininet> host1 ping -c 4 host100

        And seeing four successful replies:

            PING 10.100.0.42 (10.100.0.42) 56(84) bytes of data.
            64 bytes from 10.100.0.42: icmp_seq=1 ttl=63 time=167 ms
            64 bytes from 10.100.0.42: icmp_seq=2 ttl=63 time=101 ms
            64 bytes from 10.100.0.42: icmp_seq=3 ttl=63 time=87.0 ms
            64 bytes from 10.100.0.42: icmp_seq=4 ttl=63 time=86.8 ms

            --- 10.100.0.42 ping statistics ---
            4 packets transmitted, 4 received, 0% packet loss, time 3004ms
            rtt min/avg/max/mdev = 86.804/110.837/167.881/33.479 ms
        """
        chirouter_runner.start_mininet("3router.json")
        mn = chirouter_runner.mininet

        ping = chirouter_runner.ping("host1", "10.100.0.42", count=4)

        ping.validate_output_success(num_expected=4, expected_source="10.100.0.42")

    @pytest.mark.category("3ROUTER")
    def test_ping_host4(self, chirouter_runner):
        """
        Tests end-to-end functionality of the three-router topology by pinging
        host4 from host1. Requires most/all router functionality to be
        implemented.

        Equivalent to running this:

            mininet> host1 ping -c 4 host4

        And seeing four successful replies:

            PING 10.4.0.42 (10.4.0.42) 56(84) bytes of data.
            64 bytes from 10.4.0.42: icmp_seq=1 ttl=61 time=55.6 ms
            64 bytes from 10.4.0.42: icmp_seq=2 ttl=61 time=34.9 ms
            64 bytes from 10.4.0.42: icmp_seq=3 ttl=61 time=63.9 ms
            64 bytes from 10.4.0.42: icmp_seq=4 ttl=61 time=44.2 ms

            --- 10.4.0.42 ping statistics ---
            4 packets transmitted, 4 received, 0% packet loss, time 3004ms
            rtt min/avg/max/mdev = 34.916/49.697/63.979/11.033 ms
        """
        chirouter_runner.start_mininet("3router.json")
        mn = chirouter_runner.mininet

        ping = chirouter_runner.ping("host1", "10.4.0.42", count=4)

        ping.validate_output_success(num_expected=4, expected_source="10.4.0.42")


    @pytest.mark.category("3ROUTER")
    def test_ping_host1(self, chirouter_runner):
        """
        Tests end-to-end functionality of the three-router topology by pinging
        host1 from host4. Requires most/all router functionality to be
        implemented.

        Equivalent to running this:

            mininet> host4 ping -c 4 host1

        And seeing four successful replies:

            PING 10.1.0.42 (10.1.0.42) 56(84) bytes of data.
            64 bytes from 10.1.0.42: icmp_seq=1 ttl=61 time=48.7 ms
            64 bytes from 10.1.0.42: icmp_seq=2 ttl=61 time=41.7 ms
            64 bytes from 10.1.0.42: icmp_seq=3 ttl=61 time=21.4 ms
            64 bytes from 10.1.0.42: icmp_seq=4 ttl=61 time=51.8 ms

            --- 10.1.0.42 ping statistics ---
            4 packets transmitted, 4 received, 0% packet loss, time 3005ms
            rtt min/avg/max/mdev = 21.410/40.953/51.891/11.867 ms
        """
        chirouter_runner.start_mininet("3router.json")
        mn = chirouter_runner.mininet

        ping = chirouter_runner.ping("host4", "10.1.0.42", count=4)

        ping.validate_output_success(num_expected=4, expected_source="10.1.0.42")

class TestTraceroute:
    @pytest.mark.category("3ROUTER")
    def test_traceroute_host4(self, chirouter_runner):
        """
        Tests end-to-end functionality of the three-router topology by doing a
        traceroute from host1 to host4. Requires most/all router
        functionality to be implemented.

        Equivalent to running this:

            mininet> host1 traceroute host4

        And seeing the following:

            traceroute to 10.4.0.42 (10.4.0.42), 30 hops max, 60 byte packets
             1  10.1.0.1 (10.1.0.1)  32.651 ms  35.776 ms  35.782 ms
             2  10.100.0.1 (10.100.0.1)  71.554 ms  92.322 ms  107.198 ms
             3  10.200.0.2 (10.200.0.2)  110.819 ms  112.896 ms  152.209 ms
             4  10.4.0.42 (10.4.0.42)  152.219 ms  180.433 ms  178.299 ms
        """
        chirouter_runner.start_mininet("3router.json")

        traceroute = chirouter_runner.traceroute("host1", "10.4.0.42", max_hops=5)

        traceroute.validate_output(expected_hops = ["10.1.0.1",
                                                    "10.100.0.1",
                                                    "10.200.0.2",
                                                    "10.4.0.42"], max_timeouts=2)

    @pytest.mark.category("3ROUTER")
    def test_traceroute_host1(self, chirouter_runner):
        """
        Tests end-to-end functionality of the three-router topology by doing a
        traceroute from host4 to host1. Requires most/all router
        functionality to be implemented.

        Equivalent to running this:

            mininet> host4 traceroute host1

        And seeing the following:

            traceroute to 10.1.0.42 (10.1.0.42), 30 hops max, 60 byte packets
             1  10.4.0.1 (10.4.0.1)  22.879 ms  24.029 ms  24.031 ms
             2  10.200.0.1 (10.200.0.1)  78.251 ms  40.859 ms  76.196 ms
             3  10.100.0.2 (10.100.0.2)  82.827 ms  119.647 ms  129.343 ms
             4  10.1.0.42 (10.1.0.42)  167.517 ms  240.325 ms  174.980 ms
        """
        chirouter_runner.start_mininet("3router.json")

        traceroute = chirouter_runner.traceroute("host4", "10.1.0.42", max_hops=5)

        traceroute.validate_output(expected_hops = ["10.4.0.1",
                                                    "10.200.0.1",
                                                    "10.100.0.2",
                                                    "10.1.0.42"], max_timeouts=2)

class TestWget:

    @pytest.mark.category("3ROUTER")
    def test_wget_server(self, chirouter_runner):
        """
        Tests end-to-end functionality of the three-router topology by downloading
        a small file from the web server running in host4. Requires
        most/all router functionality to be implemented.

        Equivalent to running this:

            mininet> host1 wget -q -O - http://10.4.0.42/

        And seeing the following:

            <html>
            <head><title> This is host4</title></head>
            <body>
            Congratulations! <br/>
            Your router successfully routes your packets to and from host4.<br/>
            </body>
            </html>
        """
        chirouter_runner.start_mininet("3router.json")
        mn = chirouter_runner.mininet

        wget = chirouter_runner.wget("host1", "10.4.0.42")

        wget.validate_output("host4")

