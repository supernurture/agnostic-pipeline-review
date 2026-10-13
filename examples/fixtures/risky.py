"""Fixture: risky patterns to bait Semgrep. Do not use any of this as an example."""

import hashlib
import socket

import flask
from Crypto.Hash import MD5

app = flask.Flask(__name__)


def checksum(data):
    # Collision-prone hashes used as if they were signatures.
    return MD5.new(data).hexdigest() + hashlib.sha224(data).hexdigest()


def listen(port):
    # Bound to every interface.
    server = socket.socket()
    server.bind(("0.0.0.0", port))
    return server


if __name__ == "__main__":
    # The debugger, on every interface.
    app.run(host="0.0.0.0", debug=True)
