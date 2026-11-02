"""Bounded RTSP/1.0 framing for the diagnostic OPTIONS exchange."""
import re

HEADER_BYTES = 8192
BODY_BYTES = 8192
STREAM_BYTES = 16384
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")


def parse(data):
    """Return (message, consumed bytes), or None for incomplete input."""
    if len(data) > STREAM_BYTES:
        raise ValueError("RTSP stream exceeds limit")
    if data.startswith(b"$"):
        raise ValueError("interleaved media is outside this diagnostic")
    end = data.find(b"\r\n\r\n")
    if end < 0:
        if len(data) >= HEADER_BYTES:
            raise ValueError("RTSP header exceeds limit")
        return None
    size = end + 4
    if size > HEADER_BYTES:
        raise ValueError("RTSP header exceeds limit")
    text = data[:end].decode("ascii", "strict")
    if any(ord(c) < 32 and c not in "\r\n" for c in text) or "\x7f" in text:
        raise ValueError("RTSP header contains control bytes")
    lines = text.split("\r\n")
    first = lines[0]
    if re.fullmatch(r"RTSP/1\.0 [1-5][0-9]{2} [ -~]+", first):
        kind, status, method, uri = "response", int(first.split(" ")[1]), None, None
    else:
        match = re.fullmatch(r"([A-Z_]+) ([!-~]+) RTSP/1\.0", first)
        if not match:
            raise ValueError("invalid RTSP start line")
        kind, status = "request", None
        method, uri = match.groups()
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep or not TOKEN.fullmatch(name) or name.lower() in headers:
            raise ValueError("invalid or duplicate RTSP header")
        if "\r" in value or "\n" in value:
            raise ValueError("invalid RTSP header value")
        headers[name.lower()] = value.strip(" ")
    cseq = headers.get("cseq", "")
    if not re.fullmatch(r"[0-9]{1,10}", cseq) or int(cseq) > 2147483647:
        raise ValueError("missing/invalid RTSP CSeq")
    length = headers.get("content-length", "0")
    if not re.fullmatch(r"[0-9]{1,5}", length) or int(length) > BODY_BYTES:
        raise ValueError("invalid/oversized RTSP body")
    total = size + int(length)
    if len(data) < total:
        return None
    return dict(kind=kind, status=status, method=method, uri=uri, cseq=int(cseq),
                headers=headers, body=bytes(data[size:total]), start_line=first), total


def initial_options(message):
    if (message["kind"], message["method"], message["uri"], message["body"]) != (
            "request", "OPTIONS", "*", b""):
        raise ValueError("expected bodyless initial OPTIONS")
    if message["headers"].get("require") != "org.wfa.wfd1.0":
        raise ValueError("missing WFD Require token")


def options_reply(cseq):
    return ("RTSP/1.0 200 OK\r\nCSeq: %d\r\n"
            "Public: org.wfa.wfd1.0, OPTIONS, GET_PARAMETER, SET_PARAMETER\r\n\r\n" % cseq).encode("ascii")


def options_request():
    return (b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n"
            b"Require: org.wfa.wfd1.0\r\n\r\n")


def query_names(message):
    if message["kind"] != "request" or message["method"] != "GET_PARAMETER":
        raise ValueError("expected capability GET_PARAMETER query")
    if not message["uri"].startswith("rtsp://"):
        raise ValueError("invalid capability URI")
    if message["headers"].get("content-type", "").lower() != "text/parameters":
        raise ValueError("unexpected capability Content-Type")
    body = message["body"].decode("ascii", "strict")
    if not body.endswith("\r\n"):
        raise ValueError("capability body must end in CRLF")
    names = body[:-2].split("\r\n")
    if not 1 <= len(names) <= 64 or any(not NAME.fullmatch(n) for n in names):
        raise ValueError("invalid capability parameter names")
    if len(names) != len(set(names)):
        raise ValueError("duplicate capability parameter names")
    return names
