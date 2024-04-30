import http.server
import socketserver
import sys

class ChiRouterHTTPHandler(http.server.SimpleHTTPRequestHandler):

    # Disable logging DNS lookups
    def address_string(self):
        return str(self.client_address[0])

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-length", len(HTTP_RESPONSE))
        self.end_headers()
        self.wfile.write(bytes(HTTP_RESPONSE, "utf-8"))

server_name = sys.argv[1]

PORT = 80

HTTP_RESPONSE = """<html>
<head><title> This is {}</title></head>
<body>
Congratulations! <br/>
Your router successfully routes your packets to and from {}.<br/>
</body>
</html>""".format(server_name, server_name)

Handler = ChiRouterHTTPHandler
socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(("", PORT), Handler)
print("{}: httpd serving at port {}".format(server_name, PORT))

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    pass

httpd.server_close()
print("Server stopped.")
