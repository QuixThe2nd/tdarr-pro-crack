#!/usr/bin/env python3
"""Minimal loopback verification helper for one exact Tdarr native binary."""

import argparse
import hashlib
import hmac
import http.client
import http.server
import json
import os
import secrets
from pathlib import Path
import signal
import socket
import stat
import sys
import threading
import time

ORIGINAL_SHA256 = "b9346a2b7408b3faebcab16788cc26bf544cf090dc3a49a0e8a7db70a192a338"
PATCHED_SHA256 = "94c94523d7826ee67a7d981aff10379158e4eefb9cf9c920e3d979cc2dad74b2"
VENDOR_BASE = b"https://api.tdarr.io"
LOOPBACK_BASE = b"http://xapi.tdarr.io"
PREFIX = b"rootDataPathpluginsDir"
SUFFIX = b"assetsapppluginsTdarrPluginsnodePlugins"
UPDATER_URL = VENDOR_BASE + b"/api/v2/updater-config"
VERIFY_PATH = "/api/v2/verify-key"
HEALTH_PATH = "/__health"
UPSTREAM_HOST = "api.tdarr.io"
UPSTREAM_PORT = 443
LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 80
XAPI_HOST = "xapi.tdarr.io"
TDARR_BINARY = Path("/app/Tdarr_Server/rust/Tdarr_Server_Rust")
TDARR_API_PORT = 8266
SETTINGS_PATH = "/api/v2/cruddb"
AUTH_STATUS_PATH = "/api/v2/auth-status"
BOOTSTRAP_ATTEMPTS = 30
BOOTSTRAP_RETRY_SECONDS = 2
API_TIMEOUT = 5
INIT_EMPTY_KEY_ENV = "TDARR_ADDON_INIT_EMPTY_KEY"
LOCAL_KEY_PREFIX = "TDARR-ADDON-LOCAL-"
SEED_FILES = ("native_verifier.py", "entrypoint.sh")
MAX_REQUEST = 1024 * 1024
MAX_RESPONSE = 16 * 1024 * 1024
NETWORK_TIMEOUT = 15
HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}


class VerifierError(Exception):
    pass


class ResponseTooLarge(Exception):
    pass


class BootstrapError(Exception):
    pass


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def patch_binary(input_path, output_path):
    if os.path.lexists(output_path):
        raise VerifierError("output already exists")
    if file_sha256(input_path) != ORIGINAL_SHA256:
        raise VerifierError("input SHA-256 does not match the required original")
    original = input_path.read_bytes()
    if hashlib.sha256(original).hexdigest() != ORIGINAL_SHA256:
        raise VerifierError("input changed while being read")
    if len(VENDOR_BASE) != 20 or len(LOOPBACK_BASE) != 20:
        raise VerifierError("replacement literal length is not 20 bytes")
    if VENDOR_BASE[-4:] != b"r.io" or LOOPBACK_BASE[-4:] != b"r.io":
        raise VerifierError("compiled r.io suffix is not preserved")
    if original.count(VENDOR_BASE) != 3 or original.count(UPDATER_URL) != 2:
        raise VerifierError("vendor base/updater occurrence guards failed")
    anchor = PREFIX + VENDOR_BASE + SUFFIX
    if original.count(anchor) != 1:
        raise VerifierError("selected vendor-base context is not unique")
    offset = original.index(anchor) + len(PREFIX)
    patched = original[:offset] + LOOPBACK_BASE + original[offset + len(VENDOR_BASE):]
    if len(patched) != len(original):
        raise VerifierError("patched length differs from original")
    if patched[:offset] != original[:offset] or patched[offset + 20:] != original[offset + 20:]:
        raise VerifierError("bytes outside the selected literal changed")
    if patched.count(UPDATER_URL) != 2:
        raise VerifierError("updater URLs changed")
    changed = sum(before != after for before, after in zip(original, patched))
    if changed != 3:
        raise VerifierError("changed-byte count is not three")
    patched_hash = hashlib.sha256(patched).hexdigest()
    if patched_hash != PATCHED_SHA256:
        raise VerifierError("patched SHA-256 does not match the proven artifact")

    created = False
    try:
        with output_path.open("xb") as stream:
            created = True
            stream.write(patched)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o555)
        if file_sha256(output_path) != PATCHED_SHA256:
            raise VerifierError("written output failed its SHA-256 guard")
        if file_sha256(input_path) != ORIGINAL_SHA256:
            raise VerifierError("input changed during patching")
    except Exception:
        if created:
            try:
                output_path.unlink()
            except OSError:
                pass
        raise
    print(f"input_sha256={ORIGINAL_SHA256}")
    print(f"output_sha256={PATCHED_SHA256}")
    print(f"changed_bytes={changed}")
    print(f"offset={offset}")


def check_loopback_dns():
    try:
        answers = socket.getaddrinfo(
            XAPI_HOST, LOCAL_PORT, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise VerifierError(f"{XAPI_HOST} did not resolve") from exc
    addresses = {answer[4][0] for answer in answers}
    if not answers or addresses != {LOCAL_HOST}:
        raise VerifierError(f"{XAPI_HOST} must resolve exclusively to {LOCAL_HOST}")
    print("DNS_LOOPBACK=true")


def patch_in_place(path):
    check_loopback_dns()
    current_hash = file_sha256(path)
    if current_hash == PATCHED_SHA256:
        print(f"ALREADY_PATCHED_SHA256={PATCHED_SHA256}")
        return
    if current_hash != ORIGINAL_SHA256:
        raise VerifierError("input SHA-256 matches neither the original nor patched binary")

    source_stat = path.stat()
    temporary = path.with_name(f".{path.name}.tdarr-addon-{os.getpid()}.tmp")
    replaced = False
    try:
        patch_binary(path, temporary)
        os.chmod(temporary, stat.S_IMODE(source_stat.st_mode))
        os.chown(temporary, source_stat.st_uid, source_stat.st_gid)
        os.replace(temporary, path)
        replaced = True
        if file_sha256(path) != PATCHED_SHA256:
            raise VerifierError("atomically replaced binary failed its SHA-256 guard")
        print("ATOMIC_REPLACEMENT=true")
    finally:
        if not replaced and os.path.lexists(temporary):
            temporary.unlink()


def seed_volume(target):
    source_directory = Path(__file__).resolve().parent
    target.mkdir(parents=True, exist_ok=True)
    for name in SEED_FILES:
        source = source_directory / name
        destination = target / name
        content = source.read_bytes()
        try:
            destination_stat = destination.lstat()
            unchanged = (
                stat.S_ISREG(destination_stat.st_mode)
                and destination.read_bytes() == content
            )
        except FileNotFoundError:
            unchanged = False
        if unchanged:
            os.chmod(destination, 0o555)
            continue

        temporary = target / f".{name}.tdarr-addon-{os.getpid()}.tmp"
        try:
            with temporary.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o555)
            os.replace(temporary, destination)
        finally:
            if os.path.lexists(temporary):
                temporary.unlink()
    print(f"SEEDED_FILES={len(SEED_FILES)}")


def read_key(path):
    try:
        key = path.read_text(encoding="utf-8").strip()
    except UnicodeError as exc:
        raise VerifierError("key file must be nonempty UTF-8 text") from exc
    if not key:
        raise VerifierError("key file must be nonempty")
    return key


def bounded_response(response, limit):
    blocks = []
    total = 0
    while True:
        block = response.read(min(65536, limit + 1 - total))
        if not block:
            return b"".join(blocks)
        blocks.append(block)
        total += len(block)
        if total > limit:
            raise ResponseTooLarge()


class VerifierServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, key):
        if address[0] != LOCAL_HOST:
            raise VerifierError("verifier may bind only to 127.0.0.1")
        self.key = key.encode("utf-8") if key is not None else None
        self.state = "ready" if key is not None else "bootstrapping"
        self.serving = threading.Event()
        super().__init__(address, VerifierHandler)

    def service_actions(self):
        self.serving.set()

    def set_key(self, key):
        self.key = key.encode("utf-8")

    def mark_ready(self):
        if self.key is None:
            raise VerifierError("cannot become ready without a key")
        self.state = "ready"

    def mark_failed(self):
        self.key = None
        self.state = "failed"

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(NETWORK_TIMEOUT)
        return request, address

    def handle_error(self, _request, _client_address):
        pass


class VerifierHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NativeVerifier"
    sys_version = ""

    def log_message(self, _format, *_args):
        pass

    def parse_request(self):
        parsed = super().parse_request()
        words = self.raw_requestline.split()
        self._network_path = bool(
            parsed and len(words) >= 2 and words[1].startswith(b"//")
        )
        return parsed

    def __getattr__(self, name):
        if name.startswith("do_") and len(name) > 3:
            return self._handle_request
        raise AttributeError(name)

    def _send_json(self, status, value):
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def _request_body(self):
        if self.headers.get_all("Transfer-Encoding", []):
            self._send_json(501, {"error": "transfer encoding unsupported"})
            return None
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) > 1:
            self._send_json(400, {"error": "ambiguous content length"})
            return None
        raw_length = lengths[0] if lengths else "0"
        if not raw_length or any(char < "0" or char > "9" for char in raw_length):
            self._send_json(400, {"error": "invalid content length"})
            return None
        length = int(raw_length)
        if length > MAX_REQUEST:
            self._send_json(413, {"error": "request too large"})
            return None
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self._send_json(400, {"error": "incomplete request body"})
            return None
        return body

    def _handle_request(self):
        try:
            if self.command == "CONNECT":
                self._send_json(501, {"error": "CONNECT unsupported"})
                return
            try:
                self.path.encode("ascii")
            except UnicodeEncodeError:
                self._send_json(400, {"error": "invalid request target"})
                return
            if (self._network_path or not self.path.startswith("/") or self.path.startswith("//")
                    or "#" in self.path or any(ord(char) <= 32 or ord(char) == 127
                                               for char in self.path)):
                self._send_json(400, {"error": "origin-form target required"})
                return
            body = self._request_body()
            if body is None:
                return
            if self.command == "POST" and self.path == VERIFY_PATH:
                self._verify(body)
            elif self.command == "GET" and self.path == HEALTH_PATH:
                ready = self.server.state == "ready" and self.server.key is not None
                body = {"ready": True} if ready else {
                    "ready": False, "status": self.server.state
                }
                self._send_json(200 if ready else 503, body)
            else:
                self._proxy(body)
        except (ConnectionError, TimeoutError):
            self.close_connection = True

    do_CONNECT = _handle_request

    def _verify(self, body):
        try:
            payload = json.loads(
                body.decode("utf-8"),
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
        except (UnicodeError, ValueError, RecursionError):
            self._send_json(400, {"error": "invalid JSON request"})
            return
        candidate = payload.get("tdarrKey") if isinstance(payload, dict) else None
        try:
            candidate_bytes = candidate.encode("utf-8") if isinstance(candidate, str) else b""
            matched = (
                isinstance(candidate, str)
                and self.server.key is not None
                and hmac.compare_digest(candidate_bytes, self.server.key)
            )
        except UnicodeError:
            matched = False
        self._send_json(200, matched)

    def _proxy(self, body):
        connection = None
        try:
            connection = http.client.HTTPSConnection(
                UPSTREAM_HOST, UPSTREAM_PORT, timeout=NETWORK_TIMEOUT
            )
            connection_tokens = {
                token.strip().lower()
                for value in self.headers.get_all("Connection", [])
                for token in value.split(",")
            }
            blocked = HOP_HEADERS | connection_tokens | {"host", "content-length"}
            headers = {
                name: value for name, value in self.headers.items()
                if name.lower() not in blocked
            }
            connection.request(
                self.command, self.path, body=body if body else None, headers=headers
            )
            response = connection.getresponse()
            response_body = bounded_response(response, MAX_RESPONSE)
            response_headers = response.getheaders()
            response_tokens = {
                token.strip().lower()
                for name, value in response_headers if name.lower() == "connection"
                for token in value.split(",")
            }
            blocked = HOP_HEADERS | response_tokens | {"content-length"}
            self.send_response_only(response.status, response.reason)
            for name, value in response_headers:
                if name.lower() not in blocked:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD" and response_body:
                self.wfile.write(response_body)
            self.close_connection = True
        except (OSError, http.client.HTTPException, ResponseTooLarge):
            self._send_json(502, {"error": "bad gateway"})
        finally:
            if connection is not None:
                connection.close()


def api_request(path, payload):
    connection = http.client.HTTPConnection(
        LOCAL_HOST, TDARR_API_PORT, timeout=API_TIMEOUT
    )
    try:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        connection.request(
            "POST", path, body=body, headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        response_body = bounded_response(response, MAX_REQUEST)
        if response.status != 200:
            raise BootstrapError(f"local API returned HTTP {response.status}")
        return response_body
    except (OSError, http.client.HTTPException, ResponseTooLarge) as exc:
        raise BootstrapError("local API request failed") from exc
    finally:
        connection.close()


def read_global_settings():
    body = api_request(SETTINGS_PATH, {"data": {
        "collection": "SettingsGlobalJSONDB",
        "mode": "getById",
        "docID": "globalsettings",
    }})
    try:
        document = json.loads(
            body.decode("utf-8"),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise BootstrapError("settings response was not valid JSON") from exc
    if not isinstance(document, dict):
        raise BootstrapError("settings response was not a bare document")
    return document


def update_global_settings(document):
    api_request(SETTINGS_PATH, {"data": {
        "collection": "SettingsGlobalJSONDB",
        "mode": "update",
        "docID": "globalsettings",
        "obj": document,
    }})


def settings_key(document):
    stored_key = document.get("tdarrKey", "")
    if not isinstance(stored_key, str):
        raise BootstrapError("tdarrKey was not a string")
    return stored_key


def initialize_empty_key(document, initialization):
    if initialization["write_attempted"]:
        raise BootstrapError("empty-key initialization was already attempted")
    initialization["write_attempted"] = True

    marker = LOCAL_KEY_PREFIX + secrets.token_hex(16)
    updated = dict(document)
    updated["tdarrKey"] = marker
    update_global_settings(updated)

    readback = read_global_settings()
    original_fields = {key: value for key, value in document.items() if key != "tdarrKey"}
    readback_fields = {key: value for key, value in readback.items() if key != "tdarrKey"}
    if readback_fields != original_fields:
        raise BootstrapError("non-key settings changed during empty-key initialization")
    stored_key = settings_key(readback)
    key = stored_key.strip()
    if not key:
        raise BootstrapError("empty-key initialization readback was empty")
    initialization["verified"] = True
    return key


def bootstrap_key(initialization=None):
    document = read_global_settings()
    key = settings_key(document).strip()
    if key:
        return key
    if initialization is None or not initialization["enabled"]:
        raise BootstrapError("tdarrKey is empty")

    # Use the latest object and preserve a key supplied since the first read.
    document = read_global_settings()
    key = settings_key(document).strip()
    if key:
        return key
    return initialize_empty_key(document, initialization)


def bootstrap_api(server):
    if not server.serving.wait(NETWORK_TIMEOUT):
        server.mark_failed()
        print("API_BOOTSTRAP=failed", file=sys.stderr, flush=True)
        return
    initialization = {
        "enabled": os.environ.get(INIT_EMPTY_KEY_ENV, "false").lower() == "true",
        "write_attempted": False,
        "verified": False,
    }
    for attempt in range(1, BOOTSTRAP_ATTEMPTS + 1):
        try:
            key = bootstrap_key(initialization)
            server.set_key(key)
            # The HTTP server is already listening; auth-status can call verify-key.
            body = api_request(AUTH_STATUS_PATH, {"data": {"saU": True}})
            try:
                auth_status = json.loads(body.decode("utf-8"))
            except (UnicodeError, ValueError, RecursionError) as exc:
                raise BootstrapError("auth-status response was not valid JSON") from exc
            if auth_status is not True:
                raise BootstrapError("auth-status did not return literal true")
            server.mark_ready()
            print("API_BOOTSTRAP=ready", flush=True)
            return
        except (BootstrapError, UnicodeError, OSError, VerifierError):
            if initialization["write_attempted"] and not initialization["verified"]:
                break
            if attempt < BOOTSTRAP_ATTEMPTS:
                time.sleep(BOOTSTRAP_RETRY_SECONDS)
    server.mark_failed()
    print("API_BOOTSTRAP=failed", file=sys.stderr, flush=True)


def run_server(server, bootstrap_thread=None):
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    previous_term = signal.signal(signal.SIGTERM, interrupt)
    if bootstrap_thread is not None:
        bootstrap_thread.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        signal.signal(signal.SIGTERM, previous_term)
    return 0


def serve(key_file):
    key = read_key(key_file)
    return run_server(VerifierServer((LOCAL_HOST, LOCAL_PORT), key))


def serve_from_api():
    server = VerifierServer((LOCAL_HOST, LOCAL_PORT), None)
    bootstrap_thread = threading.Thread(
        target=bootstrap_api, args=(server,), daemon=True
    )
    return run_server(server, bootstrap_thread)


def local_request(port, method, path, payload=None):
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"} if body is not None else {}
    connection = http.client.HTTPConnection(LOCAL_HOST, port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response_body = bounded_response(response, 65536)
        return response.status, response_body
    finally:
        connection.close()


def healthcheck():
    try:
        status, body = local_request(LOCAL_PORT, "GET", HEALTH_PATH)
        ready = status == 200 and json.loads(body) == {"ready": True}
    except (OSError, ValueError, http.client.HTTPException, ResponseTooLarge):
        ready = False
    print(f"HEALTHY={str(ready).lower()}")
    return 0 if ready else 1


def check_key(key_file, intentionally_wrong=False):
    key = read_key(key_file)
    candidate = key + "-intentionally-wrong" if intentionally_wrong else key
    try:
        status, body = local_request(
            LOCAL_PORT, "POST", VERIFY_PATH, {"tdarrKey": candidate}
        )
        expected = not intentionally_wrong
        result = status == 200 and json.loads(body) is expected
    except (OSError, ValueError, http.client.HTTPException, ResponseTooLarge):
        result = False
    label = "WRONG_KEY_REJECTED" if intentionally_wrong else "KEY_ACCEPTED"
    print(f"{label}={str(result).lower()}")
    return 0 if result else 1


class StubResponse:
    def __init__(self, status=200, headers=(), body=b"", reason="Fixture"):
        self.status = status
        self.reason = reason
        self._headers = list(headers)
        self._body = body
        self._offset = 0

    def getheaders(self):
        return list(self._headers)

    def read(self, size=-1):
        if size < 0:
            size = len(self._body) - self._offset
        end = min(len(self._body), self._offset + size)
        block = self._body[self._offset:end]
        self._offset = end
        return block


class MemorySocket:
    def __init__(self, connection):
        self.connection = connection

    def sendall(self, data):
        self.connection.sent.append(data)

    def close(self):
        pass


class StubConnection(http.client.HTTPConnection):
    """Exercise stdlib request serialization without creating a network socket."""

    default_port = 443

    def __init__(self, host, port, timeout, outcome):
        super().__init__(host, port, timeout=timeout)
        self.outcome = outcome
        self.sent = []

    def connect(self):
        self.sock = MemorySocket(self)

    def getresponse(self):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class HTTPSBoundary:
    def __init__(self):
        self.outcomes = []
        self.connections = []

    def add(self, outcome):
        self.outcomes.append(outcome)

    def connect(self, host, port=443, timeout=None):
        if host != UPSTREAM_HOST or port != UPSTREAM_PORT or timeout != NETWORK_TIMEOUT:
            raise VerifierError("upstream boundary received an unexpected destination")
        if not self.outcomes:
            raise VerifierError("unexpected upstream request")
        connection = StubConnection(host, port, timeout, self.outcomes.pop(0))
        self.connections.append(connection)
        return connection


def self_test():
    dummy_key = "TDARR-SELF-TEST-DUMMY-NOT-A-LIVE-KEY"
    boundary = HTTPSBoundary()
    server = VerifierServer((LOCAL_HOST, 0), dummy_key)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    original_https = http.client.HTTPSConnection
    checks = 0

    class CheckFailed(Exception):
        pass

    def check(condition):
        nonlocal checks
        checks += 1
        if not condition:
            raise CheckFailed(sys._getframe(1).f_lineno)

    def request(method, path, payload=None, body=None, headers=None):
        request_headers = dict(headers or {})
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        connection = http.client.HTTPConnection(LOCAL_HOST, port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read(MAX_RESPONSE + 1)
        finally:
            connection.close()

    def raw_status(request_bytes):
        with socket.create_connection((LOCAL_HOST, port), timeout=5) as connection:
            connection.settimeout(5)
            connection.sendall(request_bytes)
            response = b""
            while b"\r\n" not in response:
                block = connection.recv(4096)
                if not block:
                    break
                response += block
        return int(response.split(b" ", 2)[1])

    http.client.HTTPSConnection = boundary.connect
    thread.start()
    try:
        status, _, body = request("POST", VERIFY_PATH, {"tdarrKey": dummy_key})
        check(status == 200 and body == b"true")
        for candidate in ("definitely-wrong", "", True, 42, None):
            status, _, body = request("POST", VERIFY_PATH, {"tdarrKey": candidate})
            check(status == 200 and body == b"false")
        for payload in ("true", {"data": {"tdarrKey": dummy_key}}, []):
            status, _, body = request("POST", VERIFY_PATH, payload)
            check(status == 200 and body == b"false")
        status, _, body = request("POST", VERIFY_PATH, body=b"null")
        check(status == 200 and body == b"false")
        status, _, body = request("POST", VERIFY_PATH, body=b'{"tdarrKey":')
        check(status == 400 and body == b'{"error":"invalid JSON request"}')
        status, _, body = request("GET", HEALTH_PATH)
        check(status == 200 and json.loads(body) == {"ready": True})

        boundary.add(StubResponse(body=b"method-fixture"))
        status, _, body = request("GET", VERIFY_PATH)
        check(status == 200 and body == b"method-fixture")
        check(b"".join(boundary.connections[-1].sent).startswith(
            b"GET /api/v2/verify-key HTTP/1.1\r\n"
        ))
        check(len(boundary.connections) == 1)

        encoded = b"\x1f\x8b-deterministic-encoded-fixture"
        boundary.add(StubResponse(headers=(
            ("Content-Type", "application/octet-stream"),
            ("Content-Encoding", "gzip"),
            ("Content-Length", "2"),
            ("Connection", "X-Upstream-Hop"),
            ("X-Upstream-Hop", "remove"),
            ("X-Fixture", "preserved"),
        ), body=encoded))
        status, headers, body = request(
            "POST", "/api/v2/other?case=fixture", {"fixture": "payload"},
            headers={
                "Host": "xapi.tdarr.io", "Connection": "X-Hop",
                "X-Hop": "remove", "X-Fixture": "preserved",
            },
        )
        response_headers = {name.lower(): value for name, value in headers}
        check(status == 200 and body == encoded)
        check(response_headers.get("content-encoding") == "gzip")
        check(response_headers.get("content-length") == str(len(encoded)))
        check(response_headers.get("x-fixture") == "preserved")
        check("x-upstream-hop" not in response_headers)
        upstream = boundary.connections[-1]
        wire = b"".join(upstream.sent)
        wire_headers = wire.split(b"\r\n\r\n", 1)[0].lower()
        check(b"host: api.tdarr.io\r\n" in wire_headers)
        check(b"host: xapi.tdarr.io" not in wire_headers)
        check(b"x-hop:" not in wire_headers and b"x-fixture: preserved" in wire_headers)
        check(b"post /api/v2/other?case=fixture http/1.1\r\n" in wire_headers)
        check(wire.endswith(b'{"fixture":"payload"}'))

        for method, target, expected in (
            ("GET", "https://example.invalid/api", 400),
            ("GET", "example.invalid:443", 400),
            ("GET", "//example.invalid/api", 400),
            ("OPTIONS", "*", 400),
            ("CONNECT", "example.invalid:443", 501),
        ):
            status, _, _ = request(method, target)
            check(status == expected)

        prefix = b"POST /api/v2/verify-key HTTP/1.1\r\nHost: xapi.tdarr.io\r\n"
        check(raw_status(prefix + b"Transfer-Encoding: chunked\r\n\r\n") == 501)
        check(raw_status(prefix + b"Content-Length: 1048577\r\n\r\n") == 413)
        check(raw_status(prefix + b"Content-Length: 1\r\nContent-Length: 1\r\n\r\n") == 400)

        boundary.add(OSError("deterministic upstream failure"))
        status, _, body = request("GET", "/api/v2/failure")
        check(status == 502 and body == b'{"error":"bad gateway"}')
        boundary.add(StubResponse(body=b"x" * (MAX_RESPONSE + 1)))
        status, _, body = request("GET", "/api/v2/too-large")
        check(status == 502 and body == b'{"error":"bad gateway"}')
        check(not boundary.outcomes)
    except Exception as exc:
        detail = f" check_line={exc}" if isinstance(exc, CheckFailed) else ""
        print(
            f"FIXTURE_SELF_TEST=FAIL error={type(exc).__name__} checks={checks}{detail}",
            file=sys.stderr,
        )
        print("NATIVE_ACCEPTANCE=NOT_RUN")
        return 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        http.client.HTTPSConnection = original_https
    print(f"FIXTURE_SELF_TEST=PASS checks={checks}")
    print("NATIVE_ACCEPTANCE=NOT_RUN")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    patch_parser = commands.add_parser("patch")
    patch_parser.add_argument("--input", type=Path, required=True)
    patch_parser.add_argument("--output", type=Path, required=True)
    in_place_parser = commands.add_parser("patch-in-place")
    in_place_parser.add_argument("--path", type=Path, default=TDARR_BINARY)
    commands.add_parser("check-dns")
    seed_parser = commands.add_parser("seed")
    seed_parser.add_argument("--target", type=Path, required=True)
    serve_parser = commands.add_parser("serve")
    key_source = serve_parser.add_mutually_exclusive_group(required=True)
    key_source.add_argument("--key-file", type=Path)
    key_source.add_argument("--from-api", action="store_true")
    commands.add_parser("healthcheck")
    key_parser = commands.add_parser("check-key")
    key_parser.add_argument("--key-file", type=Path, required=True)
    key_parser.add_argument("--wrong", action="store_true", help="require rejection of a wrong key")
    commands.add_parser("self-test")
    args = parser.parse_args(argv)
    try:
        if args.command == "patch":
            patch_binary(args.input, args.output)
            return 0
        if args.command == "patch-in-place":
            patch_in_place(args.path)
            return 0
        if args.command == "check-dns":
            check_loopback_dns()
            return 0
        if args.command == "seed":
            seed_volume(args.target)
            return 0
        if args.command == "serve":
            if args.from_api:
                return serve_from_api()
            return serve(args.key_file)
        if args.command == "healthcheck":
            return healthcheck()
        if args.command == "check-key":
            return check_key(args.key_file, args.wrong)
        return self_test()
    except (VerifierError, OSError) as exc:
        print(f"ERROR={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
