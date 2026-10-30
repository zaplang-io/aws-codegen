#!/usr/bin/env python3
"""Independent oracle for the Lambda rest-json byte-diff fixtures (#4).

The toolchain-free half of the rest-json byte-diff gate. It recomputes — from
scratch, with only the Python standard library — the exact on-the-wire restJson1
HTTP request bytes for a handful of Lambda operations that span the binding kinds
(httpLabel / httpQuery / httpHeader / httpPayload / JSON document body), and diffs
them against the checked-in goldens in `tests/expected/lambda_*.http`.

The goldens are "the request the hand-written `aws.binding` + `aws.restjson` codec
would produce": members placed at their HTTP locations, the URI labels
percent-encoded per AWS rules (a non-greedy label encodes "/", a greedy one keeps
it), and a real SigV4 signature over the binding's *already wire-encoded* path
(the `binding_sign` contract — the canonical URI is a single `quote_path` pass,
not the double-encode core applies to a decoded path). The Zap side (that the
GENERATED client actually PRODUCES these bytes) is proven under the real toolchain
when the compiler image catches up to derive(Json) (zaplang-io/zap#346); the
generator side (that the generated source wires each member to the right slot and
body) is proven host-only by `tests/rest_byte_diff.rs`. This script is a third,
independent implementation of the binding + SigV4 algorithm, so a regression in a
fixture — or drift in the binding/signing contract shared with zaplang-io/aws — is
caught even on a runner with no Zap toolchain. The binding signatures were
cross-checked against real botocore in zaplang-io/aws #345.

Usage:
  tools/verify_lambda_requests.py          # check the checked-in goldens (CI gate)
  tools/verify_lambda_requests.py --emit    # (re)write the goldens from the oracle
"""
import hashlib
import hmac
import os
import sys
from urllib.parse import quote

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED = os.path.join(ROOT, "tests", "expected")

# AWS's published SigV4 example credentials + timestamp (same fixed inputs as
# zaplang-io/aws tests/service_signing.main.zap), so every signature is
# deterministic and independently reproducible with botocore / any SigV4 oracle.
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
ACCESS = "AKIDEXAMPLE"
REGION = "us-east-1"
AMZ = "20150830T123600Z"
DS = "20150830"

SERVICE = "lambda"
HOST = "lambda.us-east-1.amazonaws.com"


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def signing_key(secret, ds, region, svc):
    k = hmac.new(("AWS4" + secret).encode(), ds.encode(), hashlib.sha256).digest()
    k = hmac.new(k, region.encode(), hashlib.sha256).digest()
    k = hmac.new(k, svc.encode(), hashlib.sha256).digest()
    return hmac.new(k, b"aws4_request", hashlib.sha256).digest()


def uri_encode(s, slash_safe):
    """RFC-3986 percent-encode (url.quote / url.quote_path): keep the unreserved
    set, encode everything else UPPERCASE-hex, space -> %20. `slash_safe` keeps
    "/" (whole-path form); otherwise "/" is encoded too (single-segment form)."""
    return quote(s, safe="/-_.~" if slash_safe else "-_.~")


def canonical_query(params):
    """SigV4 CanonicalQueryString (url.canonical_query): each key/value
    percent-encoded, pairs sorted by encoded key then value, joined with '&'.
    Accepts a dict (single-valued) or a list of (key, value) pairs — the latter
    carries repeated keys (a list member bound to httpQuery, #425)."""
    items = params.items() if isinstance(params, dict) else params
    enc = sorted((uri_encode(k, False), uri_encode(v, False)) for k, v in items)
    return "&".join(f"{k}={v}" for k, v in enc)


def expand_path(template, labels, greedy):
    """aws.binding.expand_path: fill {Name}/{Name+} segments, each label value
    percent-encoded (non-greedy encodes '/', greedy keeps it)."""
    out, i, n = "", 0, len(template)
    while i < n:
        if template[i] == "{":
            close = template.find("}", i)
            if close < 0:
                out += template[i:]
                break
            token = template[i + 1:close]
            if token.endswith("+"):
                out += uri_encode(greedy.get(token[:-1], ""), True)
            else:
                out += uri_encode(labels.get(token, ""), False)
            i = close + 1
        else:
            out += template[i]
            i += 1
    return out


def binding_sign(method, path_template, labels, greedy, query, headers, body, content_type,
                 service=SERVICE, host=HOST):
    """aws.binding.binding_sign: sign a binding request whose path is ALREADY
    wire-encoded (canonical URI = a single quote_path, wire target = the path
    verbatim), returning ready-to-send HTTP/1.1 text. `query` is a dict or, for
    repeated-key parameters (a list bound to httpQuery, #425), a list of pairs."""
    wire_path = expand_path(path_template, labels, greedy)

    # binding_headers: the signed transport headers + member headers (+ Content-
    # Type when the body carries one). All names lowercase.
    signed = {
        "host": host,
        "x-amz-date": AMZ,
        "x-amz-content-sha256": sha(body),
    }
    for name, value in headers.items():
        signed[name.lower()] = value
    if content_type:
        signed["content-type"] = content_type

    canon_uri = uri_encode(wire_path, True)  # non-S3: one more quote_path pass
    canon_q = canonical_query(query)
    canon_headers = "".join(f"{n}:{signed[n].strip()}\n" for n in sorted(signed))
    signed_names = ";".join(sorted(signed))
    creq = f"{method}\n{canon_uri}\n{canon_q}\n{canon_headers}\n{signed_names}\n{sha(body)}"
    scope = f"{DS}/{REGION}/{service}/aws4_request"
    sts = f"AWS4-HMAC-SHA256\n{AMZ}\n{scope}\n{sha(creq)}"
    sig = hmac.new(signing_key(SECRET, DS, REGION, service), sts.encode(), hashlib.sha256).hexdigest()
    auth = (f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, "
            f"SignedHeaders={signed_names}, Signature={sig}")

    wire = "".join(f"{n}: {signed[n]}\r\n" for n in sorted(signed))
    wire += f"content-length: {len(body)}\r\n"
    wire += f"authorization: {auth}\r\n"
    target = wire_path + (f"?{canon_q}" if canon_q else "")
    return f"{method} {target} HTTP/1.1\r\n{wire}Connection: close\r\n\r\n{body}"


# --- the pinned operations (inputs chosen to exercise each binding kind) ------

def get_function():
    # httpLabel {FunctionName} + httpQuery Qualifier, GET, no body.
    return binding_sign(
        "GET", "/2015-03-31/functions/{FunctionName}",
        {"FunctionName": "my-func"}, {}, {"Qualifier": "5"},
        {}, "", "")


def list_functions():
    # pure httpQuery (a string enum FunctionVersion, an int MaxItems, Marker),
    # GET, no body. Paginated (Marker <- NextMarker).
    return binding_sign(
        "GET", "/2015-03-31/functions",
        {}, {},
        {"FunctionVersion": "ALL", "Marker": "bWFyaw==", "MaxItems": "50"},
        {}, "", "")


def put_function_concurrency():
    # httpLabel + a JSON document body (one int member), PUT.
    body = '{"ReservedConcurrentExecutions":100}'
    return binding_sign(
        "PUT", "/2017-10-31/functions/{FunctionName}/concurrency",
        {"FunctionName": "my-func"}, {}, {},
        {}, body, "application/json")


def invoke():
    # httpLabel (a partial ARN, so ':' encodes to %3A) + httpQuery + httpHeader
    # + a raw httpPayload blob, POST.
    payload = '{"k":"v"}'
    return binding_sign(
        "POST", "/2015-03-31/functions/{FunctionName}/invocations",
        {"FunctionName": "123456789012:function:my-func"}, {},
        {"Qualifier": "PROD"},
        {"X-Amz-Invocation-Type": "Event"}, payload, "application/octet-stream")


def tag_resource():
    # httpLabel {Resource} + a JSON document **map** body (zaplang-io/zap#424):
    # the required `Tags: map<str,str>` serializes as a JSON object. Map keys are
    # emitted sorted for determinism (AWS maps are order-insensitive), so
    # {"Dept","Env"} comes out in that order. POST.
    body = '{"Tags":{"Dept":"Eng","Env":"Prod"}}'
    return binding_sign(
        "POST", "/2017-03-31/tags/{Resource}",
        {"Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-func"}, {},
        {}, {}, body, "application/json")


def create_function():
    # A JSON document body with a **nested struct** (Code), an explicitly
    # serialized nested struct carrying a **list** (VpcConfig.SubnetIds), and a
    # base64 **blob** inside the derivable Code (zaplang-io/zap#424). Members are
    # emitted in model declaration order: FunctionName, Role, Code, VpcConfig
    # (absent optionals omitted). Code is a derivable struct (`.to_json()`);
    # VpcConfig is non-derivable (it holds lists) so rides an explicit serializer.
    body = (
        '{"FunctionName":"my-func",'
        '"Role":"arn:aws:iam::123456789012:role/svc",'
        '"Code":{"ZipFile":"emlwYnl0ZXM="},'
        '"VpcConfig":{"SubnetIds":["subnet-1","subnet-2"]}}'
    )
    return binding_sign(
        "POST", "/2015-03-31/functions",
        {}, {}, {}, {}, body, "application/json")


def restjson_synth_bindings():
    # zaplang-io/zap#425: a synthetic rest-json op binding the types the HTTP
    # binding layer now renders — a bool query (`enabled=true`), an optional bool
    # query (`verbose=true`), an ISO-8601 timestamp query (`after=...`, the query
    # default), an RFC-822 timestamp header (`x-since`, the header default), and a
    # list[str] query emitted as REPEATED params (`tag=a&tag=b`, carried by the
    # binding's multi_query). Id = "a/b" is a non-greedy label, so "/" -> %2F.
    # Canonical query sorts the (encoded) pairs: after, enabled, tag, tag, verbose.
    query = [
        ("enabled", "true"),
        ("verbose", "true"),
        ("after", "2015-08-30T12:36:00Z"),
        ("tag", "b"),
        ("tag", "a"),
    ]
    headers = {"x-since": "Sun, 30 Aug 2015 12:36:00 GMT"}
    return binding_sign(
        "GET", "/t/{Id}", {"Id": "a/b"}, {}, query, headers, "", "",
        service="svc", host="svc.us-east-1.amazonaws.com")


FIXTURES = {
    "lambda_get_function": get_function,
    "lambda_list_functions": list_functions,
    "lambda_put_function_concurrency": put_function_concurrency,
    "lambda_invoke": invoke,
    "lambda_tag_resource": tag_resource,
    "lambda_create_function": create_function,
    "restjson_synth_bindings": restjson_synth_bindings,
}


def main(argv):
    emit = "--emit" in argv[1:]
    failed = False
    for name, fn in FIXTURES.items():
        computed = fn()
        path = os.path.join(EXPECTED, f"{name}.http")
        if emit:
            with open(path, "w", newline="") as fh:
                fh.write(computed)
            print(f"wrote {os.path.relpath(path, ROOT)} ({len(computed)} bytes)")
            continue
        try:
            with open(path, "r", newline="") as fh:
                expected = fh.read()
        except FileNotFoundError:
            sys.stderr.write(f"missing golden {path}; run with --emit\n")
            failed = True
            continue
        if computed != expected:
            sys.stderr.write(
                f"MISMATCH {name}\n"
                f"--- computed ---\n{computed!r}\n"
                f"--- expected ---\n{expected!r}\n"
            )
            failed = True
        else:
            print(f"ok {name} — rest-json byte-diff vector verified")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
