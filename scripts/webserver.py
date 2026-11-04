# Simple web server used by the hosts in the simulated network.
#
# Serves a page that identifies the host it is running on (the tests check
# that wget downloads the expected page through the routers).
#
# Usage: webserver.py HOST_NAME

import http.server
import socketserver
import sys

# Port the web server listens on
PORT = 80

# The page served by the web server (with the name of the host)
HTTP_RESPONSE = """<html>
<head><title> This is {server}</title></head>
<body>
Congratulations! <br/>
Your router successfully routes your packets to and from {server}.<br/>
</body>
</html>"""


class ChiRouterHTTPHandler(http.server.SimpleHTTPRequestHandler):
    '''
    Request handler that serves HTTP_RESPONSE for any GET request
    '''

    # The body of the response (set by main)
    body = b""

    def address_string(self) -> str:
        '''
        Returns:
          (str) the client's IP address (overridden to avoid logging DNS
          lookups).
        '''
        return str(self.client_address[0])

    def do_GET(self) -> None:
        '''
        Handles a GET request (for any path).

        Returns: nothing.
        '''
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)


def main() -> None:
    '''
    Runs the web server until it is interrupted.

    Returns: nothing.
    '''
    if len(sys.argv) != 2:
        print("Usage: {} HOST_NAME".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    server_name = sys.argv[1]
    ChiRouterHTTPHandler.body = bytes(HTTP_RESPONSE.format(server=server_name),
                                      "utf-8")

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("", PORT), ChiRouterHTTPHandler)
    print("{}: httpd serving at port {}".format(server_name, PORT))

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    print("Server stopped.")


if __name__ == "__main__":
    main()
