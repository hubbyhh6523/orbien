#!/usr/bin/env python3
"""Real server/client/SNI/tls-term process tests; stdlib plus openssl CLI."""
import argparse
import base64
import contextlib
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

HOST = "app.example.test"
AUTH = b"Basic " + base64.b64encode(b"alice:swordfish")
SERVER = None
CLIENT = None


def quoted(value):
    return json.dumps(str(value).replace("\\", "/"))


def free_ports(count):
    with contextlib.ExitStack() as stack:
        sockets = [
            stack.enter_context(socket.socket())
            for _ in range(count)
        ]
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]


def decode_requests(data):
    """Independent backend oracle: never imports the proxy's HTTP parser."""
    requests = []
    pos = 0

    while pos < len(data):
        end = data.find(b"\r\n\r\n", pos)
        if end < 0:
            raise AssertionError(
                "backend received an incomplete request head"
            )

        lines = data[pos:end].split(b"\r\n")
        method, target, version = lines[0].split(b" ")
        assert version in (b"HTTP/1.0", b"HTTP/1.1")

        headers = {}
        for line in lines[1:]:
            name, value = line.split(b":", 1)
            headers.setdefault(name.lower(), []).append(value.strip())

        pos = end + 4
        body = bytearray()

        if b"transfer-encoding" in headers:
            assert headers[b"transfer-encoding"] == [b"chunked"]

            while True:
                end = data.find(b"\r\n", pos)
                if end < 0:
                    raise AssertionError("incomplete chunk size")

                size = int(data[pos:end].split(b";", 1)[0], 16)
                pos = end + 2

                if size == 0:
                    while True:
                        end = data.find(b"\r\n", pos)
                        if end < 0:
                            raise AssertionError("incomplete trailers")
                        empty = end == pos
                        pos = end + 2
                        if empty:
                            break
                    break

                assert pos + size + 2 <= len(data), (
                    "incomplete chunk data"
                )
                body.extend(data[pos:pos + size])
                pos += size
                assert data[pos:pos + 2] == b"\r\n"
                pos += 2

        elif b"content-length" in headers:
            assert len(headers[b"content-length"]) == 1
            size = int(headers[b"content-length"][0])
            assert pos + size <= len(data), (
                "incomplete Content-Length body"
            )
            body.extend(data[pos:pos + size])
            pos += size

        requests.append((method, target, headers, bytes(body)))

    return requests


class Backend(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.records = queue.Queue()
        super().__init__(("127.0.0.1", 0), BackendHandler)


class BackendHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytearray()

        try:
            self.request.settimeout(0.25)
            deadline = time.monotonic() + 4

            while time.monotonic() < deadline:
                try:
                    chunk = self.request.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data.extend(chunk)
                assert len(data) < 4 * 1024 * 1024

            # Deliberately ignore incoming Connection: close. The forwarder
            # must frame this response instead of waiting for backend EOF.
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Connection: keep-alive\r\n\r\nOK"
            )

            self.request.settimeout(0.75)
            while time.monotonic() < deadline:
                try:
                    chunk = self.request.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data.extend(chunk)

            self.server.records.put(
                (decode_requests(bytes(data)), None)
            )
        except Exception as error:
            self.server.records.put((None, repr(error)))


class Chain:
    def __init__(self, tls):
        self.tls = tls
        self.children = []
        self.logs = []
        self.temp = tempfile.TemporaryDirectory(
            prefix="orbien-issue18-"
        )
        self.directory = Path(self.temp.name)
        self.backend = Backend()
        self.thread = threading.Thread(
            target=self.backend.serve_forever,
            daemon=True,
        )
        self.thread.start()
        self.control, self.port = free_ports(2)

    def spawn(self, binary, config, name):
        config_path = self.directory / (name + ".toml")
        log_path = self.directory / (name + ".log")
        config_path.write_text(config, encoding="utf-8")

        log = log_path.open("wb")
        self.logs.append(log)

        process = subprocess.Popen(
            [str(binary), "-c", str(config_path)],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env={**os.environ, "RUST_LOG": "info"},
        )
        self.children.append(process)
        return log_path

    def wait_log(self, path, marker):
        deadline = time.monotonic() + 20

        while time.monotonic() < deadline:
            text = path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            if marker in text:
                return

            if any(
                child.poll() is not None
                for child in self.children
            ):
                raise AssertionError(
                    "child exited during startup\n" + self.log_text()
                )
            time.sleep(0.05)

        raise AssertionError(
            "startup deadline exceeded\n" + self.log_text()
        )

    def log_text(self):
        return "\n".join(
            p.name
            + ":\n"
            + p.read_text(encoding="utf-8", errors="replace")
            for p in self.directory.glob("*.log")
        )

    def __enter__(self):
        try:
            gateway = "httpsGwPort" if self.tls else "httpGwPort"

            server_config = f"""listen = "127.0.0.1:{self.control}"
proxyAddr = "127.0.0.1"
{gateway} = {self.port}
rootDomain = "example.test"
[auth]
token = "issue18-local-process-test-token-7ed58f3b"
[transport]
tcpMux = false
[transport.tls]
force = false
"""
            server_log = self.spawn(
                SERVER,
                server_config,
                "server",
            )
            self.wait_log(server_log, "gateway listener ready")

            backend = self.backend.server_address[1]

            client_config = f"""server = "127.0.0.1:{self.control}"
[auth]
token = "issue18-local-process-test-token-7ed58f3b"
[transport]
protocol = "tcp"
tcpMux = false
poolCount = 2
[transport.tls]
enable = false
[[tunnels]]
name = "issue18-test"
protocol = "{'https' if self.tls else 'http'}"
domains = ["{HOST}"]
"""
            if self.tls:
                cert = self.directory / "cert.pem"
                key = self.directory / "key.pem"

                subprocess.run(
                    [
                        "openssl",
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-days",
                        "1",
                        "-keyout",
                        str(key),
                        "-out",
                        str(cert),
                        "-subj",
                        "/CN=" + HOST,
                        "-addext",
                        "subjectAltName=DNS:" + HOST,
                        "-addext",
                        "basicConstraints=critical,CA:FALSE",
                        "-addext",
                        "extendedKeyUsage=serverAuth",
                        "-addext",
                        "keyUsage=digitalSignature,keyEncipherment",
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )

                self.context = ssl.create_default_context(
                    cafile=str(cert)
                )
                self.context.set_alpn_protocols(["http/1.1"])

                client_config += f"""[tunnels.plugin]
type = "tls-term"
service = "127.0.0.1:{backend}"
certFile = {quoted(cert)}
keyFile = {quoted(key)}
hostHeaderRewrite = "backend.example"
[tunnels.plugin.requestHeaders.set]
X-App = "trusted"
"""
            else:
                client_config += f"""service = "127.0.0.1:{backend}"
hostHeaderRewrite = "backend.example"
basicAuthUser = "alice"
basicAuthPassword = "swordfish"
"""

            self.spawn(CLIENT, client_config, "client")
            self.wait_log(
                server_log,
                "https tunnel registered"
                if self.tls
                else "http tunnel registered",
            )
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, kind, value, tb):
        if kind:
            print(self.log_text())

        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)

        for log in self.logs:
            log.close()

        self.backend.shutdown()
        self.backend.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def exchange(self, request):
        raw = socket.create_connection(
            ("127.0.0.1", self.port),
            timeout=4,
        )

        with raw:
            stream = (
                self.context.wrap_socket(
                    raw,
                    server_hostname=HOST,
                )
                if self.tls
                else raw
            )

            with contextlib.closing(stream):
                stream.settimeout(4)

                # A single sendall contains BOTH requests. The backend parser
                # and request count, not merely client EOF, are the oracle.
                stream.sendall(request)

                result = bytearray()
                while True:
                    chunk = stream.recv(65536)
                    if not chunk:
                        return bytes(result)
                    result.extend(chunk)


def first_request(
    method=b"GET",
    extra=b"",
    body=b"",
    host=HOST.encode(),
    auth=AUTH,
    path=b"/first",
):
    return (
        method
        + b" "
        + path
        + b" HTTP/1.1\r\nHost: "
        + host
        + b"\r\nAuthorization: "
        + auth
        + b"\r\nConnection: keep-alive\r\n"
        + b"X-App: forged-a\r\nx-app: forged-b\r\n"
        + b"X-Forwarded-For: forged\r\n"
        + extra
        + b"\r\n"
        + body
    )


class SingleRequestProcessTests(unittest.TestCase):
    def run_chain(self, tls):
        second_same = first_request(path=b"/second")

        second_changed = first_request(
            host=b"attacker.example.test",
            path=b"/admin",
            auth=b"Basic ZXY6aWw=",
        )

        payload = b"\x00\xff\xfe\r\nHost: body\r\n"
        chunked = (
            format(len(payload), "x").encode()
            + b";x=test\r\n"
            + payload
            + b"\r\n0\r\nX-Note: ignored\r\n\r\n"
        )

        cases = [
            (
                "two_gets",
                first_request() + second_same,
                b"",
            ),
            (
                "post_then_second",
                first_request(
                    b"POST",
                    b"Content-Length: "
                    + str(len(payload)).encode()
                    + b"\r\n",
                    payload,
                )
                + second_changed,
                payload,
            ),
            (
                "chunked_then_second",
                first_request(
                    b"POST",
                    b"Transfer-Encoding: chunked\r\n"
                    b"Trailer: X-Note\r\n",
                    chunked,
                )
                + second_changed,
                payload,
            ),
            (
                "changed_host_path_credentials",
                first_request() + second_changed,
                b"",
            ),
        ]

        with Chain(tls) as chain:
            total = 0

            for label, wire, expected_body in cases:
                with self.subTest(
                    chain="tls-term" if tls else "http",
                    case=label,
                ):
                    response = chain.exchange(wire)

                    self.assertTrue(
                        response.startswith(b"HTTP/1.1 200 "),
                        response,
                    )
                    self.assertTrue(
                        response.endswith(b"\r\n\r\nOK"),
                        response,
                    )
                    self.assertIn(
                        b"Connection: close\r\n",
                        response,
                    )

                    records, error = chain.backend.records.get(
                        timeout=5
                    )
                    self.assertIsNone(error)
                    self.assertEqual(
                        len(records),
                        1,
                        (label, records),
                    )
                    total += len(records)

                    method, target, headers, received = records[0]

                    self.assertEqual(target, b"/first")
                    self.assertEqual(received, expected_body)
                    self.assertEqual(
                        headers[b"host"],
                        [b"backend.example"],
                    )
                    self.assertEqual(
                        headers[b"authorization"],
                        [AUTH],
                    )
                    self.assertEqual(
                        headers[b"x-forwarded-for"],
                        [b"127.0.0.1"],
                    )
                    self.assertEqual(
                        headers[b"x-forwarded-proto"],
                        [b"https" if tls else b"http"],
                    )
                    self.assertEqual(
                        headers[b"connection"],
                        [b"close"],
                    )

                    if tls:
                        self.assertEqual(
                            headers[b"x-app"],
                            [b"trusted"],
                        )

            self.assertEqual(total, 4)
            self.assertTrue(chain.backend.records.empty())

            if not tls:
                denied = chain.exchange(
                    first_request(
                        auth=b"Basic YmFkOmJhZA=="
                    )
                )
                self.assertTrue(
                    denied.startswith(b"HTTP/1.1 401 "),
                    denied,
                )

                unknown = chain.exchange(
                    first_request(
                        host=b"missing.example.test"
                    )
                )
                self.assertTrue(
                    unknown.startswith(b"HTTP/1.1 404 "),
                    unknown,
                )
                self.assertTrue(
                    chain.backend.records.empty()
                )

    def test_real_http_gateway_chain(self):
        self.run_chain(False)

    def test_real_sni_tls_term_chain(self):
        self.run_chain(True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--client", required=True, type=Path)

    args, rest = parser.parse_known_args()
    SERVER = args.server.resolve()
    CLIENT = args.client.resolve()

    if not SERVER.is_file() or not CLIENT.is_file():
        parser.error(
            "build the real server/client binaries first"
        )

    if shutil.which("openssl") is None:
        parser.error(
            "openssl CLI is required for the TLS integration certificate"
        )

    unittest.main(
        argv=[__file__] + rest,
        verbosity=2,
    )
