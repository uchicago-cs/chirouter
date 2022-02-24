import pytest


class TestICMP(object):

    @pytest.mark.category("2ROUTER")
    def test_ping_server(self, chirouter_runner):
        """
        Tests end-to-end functionality of the two-router topology by pinging
        host "server" from client100. Requires most/all router functionality
        to be implemented, including gateway routes and Longest Prefix Match.

        Equivalent to running this:

            mininet> client100 ping -c 4 server

        And seeing four successful replies:

            PING 172.16.0.2 (172.16.0.2) 56(84) bytes of data.
            64 bytes from 172.16.0.2: icmp_seq=1 ttl=62 time=22.0 ms
            64 bytes from 172.16.0.2: icmp_seq=2 ttl=62 time=14.3 ms
            64 bytes from 172.16.0.2: icmp_seq=3 ttl=62 time=21.1 ms
            64 bytes from 172.16.0.2: icmp_seq=4 ttl=62 time=47.0 ms

            --- 172.16.0.2 ping statistics ---
            4 packets transmitted, 4 received, 0% packet loss, time 3003ms
            rtt min/avg/max/mdev = 14.397/26.179/47.084/12.428 ms
        """
        chirouter_runner.start_mininet("2router.json")

        ping = chirouter_runner.ping("client100", "172.16.0.2", count=4)

        ping.validate_output_success(num_expected=4, expected_source="172.16.0.2")

    @pytest.mark.category("2ROUTER")
    def test_ping_client100(self, chirouter_runner):
        """
        Tests end-to-end functionality of the two-router topology by pinging
        client100 from host "server". Requires most/all router functionality
        to be implemented, including gateway routes and Longest Prefix Match.

        Equivalent to running this:

            erver ping -c 4 client100

        And seeing four successful replies:

            PING 10.0.100.42 (10.0.100.42) 56(84) bytes of data.
            64 bytes from 10.0.100.42: icmp_seq=1 ttl=62 time=40.5 ms
            64 bytes from 10.0.100.42: icmp_seq=2 ttl=62 time=15.6 ms
            64 bytes from 10.0.100.42: icmp_seq=3 ttl=62 time=41.2 ms
            64 bytes from 10.0.100.42: icmp_seq=4 ttl=62 time=16.5 ms

            --- 10.0.100.42 ping statistics ---
            4 packets transmitted, 4 received, 0% packet loss, time 3004ms
            rtt min/avg/max/mdev = 15.620/28.472/41.226/12.413 ms
        """
        chirouter_runner.start_mininet("2router.json")

        ping = chirouter_runner.ping("server", "10.0.100.42", count=4)

        ping.validate_output_success(num_expected=4, expected_source="10.0.100.42")

class TestTraceroute:

    @pytest.mark.category("2ROUTER")
    def test_traceroute_server(self, chirouter_runner):
        """
        Tests end-to-end functionality of the two-router topology by doing a
        traceroute from client100 to host "server". Requires most/all router
        functionality to be implemented, including gateway routes and Longest
        Prefix Match.

        Equivalent to running this:

            mininet> client100 traceroute server

        And seeing the following:

            traceroute to 172.16.0.2 (172.16.0.2), 30 hops max, 60 byte packets
             1  10.0.100.1 (10.0.100.1)  46.325 ms  46.805 ms  46.789 ms
             2  192.168.1.1 (192.168.1.1)  93.086 ms  100.558 ms  99.434 ms
             3  172.16.0.2 (172.16.0.2)  100.553 ms  102.179 ms  136.987 ms
        """
        chirouter_runner.start_mininet("2router.json")

        traceroute = chirouter_runner.traceroute("client100", "172.16.0.2", max_hops=5)

        traceroute.validate_output(expected_hops = ["10.0.100.1",
                                                    "192.168.1.1",
                                                    "172.16.0.2"], max_timeouts=2)

    @pytest.mark.category("2ROUTER")
    def test_traceroute_client100(self, chirouter_runner):
        """
        Tests end-to-end functionality of the two-router topology by doing a
        traceroute from host "server" to client100. Requires most/all router
        functionality to be implemented, including gateway routes and Longest
        Prefix Match.

        Equivalent to running this:

            mininet> server traceroute client100

        And seeing the following:

            traceroute to 10.0.100.42 (10.0.100.42), 30 hops max, 60 byte packets
             1  172.16.0.1 (172.16.0.1)  39.088 ms  39.699 ms  39.682 ms
             2  192.168.1.10 (192.168.1.10)  57.754 ms  92.252 ms  90.556 ms
             3  10.0.100.42 (10.0.100.42)  92.981 ms  158.096 ms  160.074 ms
        """
        chirouter_runner.start_mininet("2router.json")

        traceroute = chirouter_runner.traceroute("server", "10.0.100.42", max_hops=5)

        traceroute.validate_output(expected_hops = ["172.16.0.1",
                                                    "192.168.1.10",
                                                    "10.0.100.42"], max_timeouts=2)

class TestWget:

    @pytest.mark.category("2ROUTER")
    def test_wget_server(self, chirouter_runner):
        """
        Tests end-to-end functionality of the two-router topology by downloading
        a small file from the web server running in host "server". Requires
        most/all router functionality to be implemented, including gateway routes
        and Longest Prefix Match.

        Equivalent to running this:

            mininet> client100 wget -q -O - http://172.16.0.2/

        And seeing the following:

            <html>
            <head><title> This is server</title></head>
            <body>
            Congratulations! <br/>
            Your router successfully routes your packets to and from server.<br/>
            </body>
            </html>
        """
        chirouter_runner.start_mininet("2router.json")

        wget = chirouter_runner.wget("client100", "172.16.0.2")

        wget.validate_output("server")

