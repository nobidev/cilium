# NOTE: Keep in sync with the copy used by the Cilium CLI tests and stored
# in cilium-cli/enterprise/hooks/cli/privnet/manifests/vm-echo-script.py
# We have two separate copies to account for the deletion of the cilium-cli
# directory in stable branches.

import os
import json
import socket
import ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer


class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

        addr = ipaddress.ip_address(self.address_string())
        addr = addr.ipv4_mapped or addr

        resp = json.dumps({
          "network": network,
          "client-ip": str(addr),
        })
        self.wfile.write(bytes(resp, encoding='utf-8'))


network = os.getenv("CILIUM_PRIVNET_NETWORK", default="default")
port = os.getenv("CILIUM_PRIVNET_PORT", default="8000")
HTTPServerV6(("::", int(port)), Handler).serve_forever()
