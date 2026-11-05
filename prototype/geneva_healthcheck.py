import errno
import hashlib
import http.client
import json
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

SCHEMA_VERSION = 1
FILE_BYTES = 256 * 1024

def reference_payload():
    seed = b"geneva-healthcheck-file-v1:"
    return b"".join(hashlib.sha256(seed + str(i).encode("ascii")).digest()
                    for i in range(FILE_BYTES // 32))

REFERENCE_SHA256 = hashlib.sha256(reference_payload()).hexdigest()

def diagnose(observation):
    """Use only a fixed whitelist of endpoint observations. Abstain on cause."""
    o = {key: observation.get(key) for key in (
        "connected", "stage", "status", "bytes_received", "declared_bytes",
        "sha256", "expected_sha256", "expected_bytes", "error_kind", "errno")}
    evidence = []
    complete = (o["connected"] is True and o["status"] == 200
                and o["error_kind"] is None
                and o["declared_bytes"] == o["expected_bytes"]
                and o["bytes_received"] == o["expected_bytes"]
                and o["sha256"] == o["expected_sha256"])
    if complete:
        symptom = "verified_delivery"
        evidence = ["HTTP 200", "Exact expected length", "SHA-256 matches reference"]
    elif o["error_kind"] == "connection_refused":
        symptom = "connection_refused"
        evidence = ["TCP connection was refused before HTTP exchange"]
    elif o["error_kind"] == "reset":
        symptom = "reset_observed"
        evidence = ["Socket reported a connection reset at stage " + str(o["stage"])]
    elif o["error_kind"] == "timeout":
        symptom = "connect_timeout" if not o["connected"] else "transfer_timeout"
        evidence = ["Timeout at stage " + str(o["stage"]),
                    "Received %s of %s expected bytes" % (o["bytes_received"], o["expected_bytes"])]
    elif o["status"] is not None and o["status"] != 200:
        symptom = "http_status_failure"
        evidence = ["HTTP status %s" % o["status"]]
    elif o["error_kind"]:
        symptom = "protocol_or_transport_error"
        evidence = ["Endpoint error: " + str(o["error_kind"])]
    elif o["status"] == 200 and o["bytes_received"] != o["expected_bytes"]:
        symptom = "incomplete_or_wrong_length"
        evidence = ["Received %s of %s expected bytes" % (o["bytes_received"], o["expected_bytes"])]
    elif o["status"] == 200 and o["sha256"] != o["expected_sha256"]:
        symptom = "integrity_mismatch"
        evidence = ["Expected length received but SHA-256 differs"]
    else:
        symptom = "unverified_delivery"
        evidence = ["Evidence is insufficient for verified delivery"]
    return {"delivery_verified": complete, "symptom": symptom, "evidence": evidence,
            "root_cause": "not_inferred" if complete else "undetermined",
            "censorship_attribution": "not_inferred"}

def measure(server, port, host_header="benign.example", timeout=10.0):
    """One real HTTP/1.1 GET and reference-file SHA-256 verification.

    The Host header is deliberately controlled; no DNS lookup of it is made.
    The connection target must be the numeric IPv4 address of the local test server.
    """
    socket.inet_aton(server)
    if any(c in host_header for c in "\r\n"):
        raise ValueError("Host header cannot contain newlines")
    request = ("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host_header).encode("ascii")
    o = dict(schema_version=SCHEMA_VERSION, connected=False, stage="connect",
             status=None, bytes_received=0, declared_bytes=None,
             expected_bytes=FILE_BYTES, expected_sha256=REFERENCE_SHA256,
             sha256=None, error_kind=None, errno=None, error_message=None,
             connect_ms=None, headers_ms=None, total_ms=None)
    start = time.monotonic(); deadline = start + float(timeout)
    digest=hashlib.sha256(); sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    response=None
    def set_remaining():
        remaining=deadline-time.monotonic()
        if remaining <= 0: raise socket.timeout("Total transfer deadline exceeded")
        sock.settimeout(remaining)
    try:
        set_remaining(); sock.connect((server,int(port)))
        o["connected"]=True; o["connect_ms"]=round((time.monotonic()-start)*1000,3)
        o["stage"]="request"; set_remaining(); sock.sendall(request)
        o["stage"]="headers"; set_remaining()
        response=http.client.HTTPResponse(sock); response.begin()
        o["status"]=response.status
        declared=response.getheader("Content-Length")
        o["declared_bytes"]=int(declared) if declared is not None else None
        o["headers_ms"]=round((time.monotonic()-start)*1000,3)
        o["stage"]="body"
        while True:
            set_remaining(); chunk=response.read(8192)
            if not chunk: break
            digest.update(chunk); o["bytes_received"]+=len(chunk)
            if o["bytes_received"] > FILE_BYTES:
                o["error_kind"]="oversized_response"; break
        o["stage"]="finished"
    except socket.timeout as exc:
        o["error_kind"]="timeout"; o["error_message"]=str(exc)
    except OSError as exc:
        o["errno"]=exc.errno; o["error_message"]=str(exc)
        if exc.errno == errno.ECONNREFUSED: o["error_kind"]="connection_refused"
        elif exc.errno == errno.ECONNRESET: o["error_kind"]="reset"
        else: o["error_kind"]="socket_error"
    except (http.client.HTTPException,ValueError) as exc:
        o["error_kind"]="http_protocol_error"; o["error_message"]=str(exc)
    finally:
        if response is not None: response.close()
        sock.close()
        o["sha256"]=digest.hexdigest()
        o["total_ms"]=round((time.monotonic()-start)*1000,3)
    return {"observation":o,"diagnosis":diagnose(o)}

def make_server(address, mode="normal", delay=0.0):
    """Controlled local reference-file server; mode is ground truth, not diagnosis input."""
    if mode not in ("normal","truncate","corrupt","status503","delay"):
        raise ValueError("Unknown server mode")
    payload=reference_payload()
    class Handler(BaseHTTPRequestHandler):
        protocol_version="HTTP/1.1"
        def log_message(self,*args): pass
        def do_GET(self):
            self.close_connection=True
            if mode=="delay": time.sleep(delay)
            try:
                body=payload
                if mode=="corrupt": body=b"X"+payload[1:]
                status=503 if mode=="status503" else 200
                self.send_response(status)
                self.send_header("Content-Type","application/octet-stream")
                self.send_header("Content-Length",str(len(payload)))
                self.send_header("Connection","close")
                self.end_headers()
                if mode=="truncate": body=body[:len(payload)//2]
                self.wfile.write(body); self.wfile.flush()
            except (OSError,ValueError):
                
                pass
    class ReusableHTTPServer(HTTPServer):
        allow_reuse_address=True
        def handle_error(self,request,client_address): pass
    return ReusableHTTPServer(address,Handler)

if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest="command")
    serve=sub.add_parser("serve"); serve.add_argument("--port",type=int,default=18081)
    serve.add_argument("--mode",default="normal"); serve.add_argument("--delay",type=float,default=0)
    probe=sub.add_parser("probe"); probe.add_argument("--server",default="127.0.0.1")
    probe.add_argument("--port",type=int,default=18081)
    probe.add_argument("--host-header",default="benign.example")
    args=parser.parse_args()
    if args.command=="serve": make_server(("127.0.0.1",args.port),args.mode,args.delay).serve_forever()
    elif args.command=="probe": print(json.dumps(measure(args.server,args.port,args.host_header),indent=2))
    else: parser.print_help()
