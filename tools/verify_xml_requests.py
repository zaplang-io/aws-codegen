#!/usr/bin/env python3
"""Independent oracle for the XML-family byte-diff fixtures (#354).

The toolchain-free half of the rest-xml + query/ec2 byte-diff gate. It recomputes
— from scratch, with only the Python standard library — the exact on-the-wire
HTTP request bytes the hand-written `aws.restxml` / `aws.query` codecs
(zaplang-io/aws #352/#353) would produce for a representative operation of each
protocol, and diffs them against the checked-in goldens in `tests/expected/`.

Coverage (the inputs are chosen to exercise each serialization trait):
  * rest-xml (CloudFront) — a default-namespace XML document body with a nested
    structure and a wrapped list (CreateInvalidation), and a two-scalar body
    (CreateCloudFrontOriginAccessIdentity), each signed via the binding layer's
    `binding_sign` (the path is already wire-encoded; canonical URI is one
    `quote_path` pass for the non-S3 service).
  * rest-xml (synthetic) — a prefixed-namespace root carrying an xmlAttribute and
    a *flattened* list, the traits no small real rest-xml service in botocore
    carries (S3/Route53 only); generated from an inline model through the real
    generator, same as the binding.rs synthetic coverage.
  * query (SimpleDB) — a flat form-urlencoded body with scalars, a flattened
    list and a boolean (GetAttributes), signed via core `sign_request` (POST "/").
  * query (STS) — the empty-input body (GetCallerIdentity: Action/Version only)
    and optional scalar members incl. an integer and a url-encoding value
    (GetSessionToken); STS is the first generated-is-product service (#355).
  * ec2 (EC2) — the ec2 key variant: Capitalized keys + an always-flattened list
    (MonitorInstances).
  * rest-xml (S3) — the S3 binding variant (canonical URI verbatim, no second
    quote_path pass; greedy {Key+} object keys): a bucket op (HeadBucket), a
    service listing (ListBuckets), an object GET (ListParts) and an object PUT
    with a raw body (UploadPart). S3 is the #356 generated-is-product service.

This is a third, independent implementation of the serialize + SigV4 algorithm
(besides `aws.restxml`/`aws.query` and the Rust reconstruction in
`tests/xml_byte_diff.rs` / `tests/query_byte_diff.rs`), so a fixture regression —
or drift in the contract shared with zaplang-io/aws — is caught even on a runner
with no Zap toolchain. The signatures use AWS's published example credentials.

Usage:
  tools/verify_xml_requests.py          # check the checked-in goldens (CI gate)
  tools/verify_xml_requests.py --emit   # (re)write the goldens from the oracle
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

CF_NS = "http://cloudfront.amazonaws.com/doc/2015-09-17/"


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def signing_key(secret, ds, region, svc):
    k = hmac.new(("AWS4" + secret).encode(), ds.encode(), hashlib.sha256).digest()
    k = hmac.new(k, region.encode(), hashlib.sha256).digest()
    k = hmac.new(k, svc.encode(), hashlib.sha256).digest()
    return hmac.new(k, b"aws4_request", hashlib.sha256).digest()


def uri_encode(s, slash_safe):
    """RFC-3986 percent-encode (url.quote / url.quote_path): keep the unreserved
    set, encode everything else UPPERCASE-hex, space -> %20."""
    return quote(s, safe="/-_.~" if slash_safe else "-_.~")


def regional_host(service):
    """aws.endpoints.resolve_service_host for the aws partition, us-east-1."""
    return f"{service}.{REGION}.amazonaws.com"


# --- rest-xml: a minimal deterministic XML serializer (mirrors core `xml`) ----

class Elem:
    """A tiny XML element: attributes and children in insertion order, exactly
    the determinism `xml.dumps` guarantees (no sort; leaf empty -> self-closing;
    text escapes & < >; attribute values escape & < ")."""

    def __init__(self, tag):
        self.tag = tag
        self.attrs = []  # (name, value) in insertion order
        self.children = []  # Elem
        self.text = None

    def attr(self, name, value):
        self.attrs.append((name, value))
        return self

    def child(self, tag):
        c = Elem(tag)
        self.children.append(c)
        return c

    def scalar(self, tag, text):
        c = self.child(tag)
        c.text = text
        return self


def esc_text(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def esc_attr(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")


def dumps(e):
    a = "".join(f' {n}="{esc_attr(v)}"' for n, v in e.attrs)
    if e.text is not None:
        return f"<{e.tag}{a}>{esc_text(e.text)}</{e.tag}>"
    if not e.children:
        return f"<{e.tag}{a}/>"
    inner = "".join(dumps(c) for c in e.children)
    return f"<{e.tag}{a}>{inner}</{e.tag}>"


# --- SigV4 signers ------------------------------------------------------------

def binding_sign(service, host, method, path_template, labels, query, body, content_type):
    """aws.binding.binding_sign (non-S3): the binding's path is already wire-
    encoded, so the canonical URI is a single quote_path pass and the wire target
    is the path verbatim. Used by rest-xml (via rest_xml_sign)."""
    wire_path = expand_path(path_template, labels)
    signed = {
        "host": host,
        "x-amz-date": AMZ,
        "x-amz-content-sha256": sha(body),
    }
    if content_type:
        signed["content-type"] = content_type
    canon_uri = uri_encode(wire_path, True)
    canon_q = canonical_query(query)
    canon_headers = "".join(f"{n}:{signed[n].strip()}\n" for n in sorted(signed))
    names = ";".join(sorted(signed))
    creq = f"{method}\n{canon_uri}\n{canon_q}\n{canon_headers}\n{names}\n{sha(body)}"
    return assemble(service, method, wire_path, canon_q, signed, names, creq, body)


def s3_expand_path(template, labels, greedy):
    """aws.binding.expand_path: {Name} is a non-greedy label (encodes "/"),
    {Name+} is a greedy label (keeps "/", e.g. an S3 object key)."""
    out, i, n = "", 0, len(template)
    while i < n:
        if template[i] == "{":
            close = template.find("}", i)
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


def s3_binding_sign(method, path_template, labels, greedy, query, headers, body, content_type):
    """aws.binding.binding_sign for the S3 service. S3 disables path
    normalization, so `canonical_uri_encoded` returns the already-wire-encoded
    path VERBATIM — no second quote_path pass (unlike the non-S3 services). The
    host is the path-style regional endpoint (s3.<region>.amazonaws.com), greedy
    {Key+} labels keep "/", and member headers are signed alongside the transport
    headers. Used by the generated rest-xml S3 client (via rest_xml_sign)."""
    wire_path = s3_expand_path(path_template, labels, greedy)
    signed = {
        "host": regional_host("s3"),
        "x-amz-date": AMZ,
        "x-amz-content-sha256": sha(body),
    }
    for name, value in headers.items():
        signed[name.lower()] = value
    if content_type:
        signed["content-type"] = content_type
    canon_uri = wire_path  # S3: the wire path verbatim, no extra encode pass.
    canon_q = canonical_query(query)
    canon_headers = "".join(f"{n}:{signed[n].strip()}\n" for n in sorted(signed))
    names = ";".join(sorted(signed))
    creq = f"{method}\n{canon_uri}\n{canon_q}\n{canon_headers}\n{names}\n{sha(body)}"
    return assemble("s3", method, wire_path, canon_q, signed, names, creq, body)


def query_sign(service, host, body):
    """aws.core.sign_request for a query/ec2 request: POST "/", the form body,
    canonical URI double-encoded for the non-S3 service (here just "/")."""
    signed = {
        "content-type": "application/x-www-form-urlencoded; charset=utf-8",
        "host": host,
        "x-amz-content-sha256": sha(body),
        "x-amz-date": AMZ,
    }
    canon_uri = uri_encode(uri_encode("/", True), True)  # non-S3 double-encode
    canon_headers = "".join(f"{n}:{signed[n].strip()}\n" for n in sorted(signed))
    names = ";".join(sorted(signed))
    creq = f"POST\n{canon_uri}\n\n{canon_headers}\n{names}\n{sha(body)}"
    return assemble(service, "POST", "/", "", signed, names, creq, body)


def assemble(service, method, wire_path, canon_q, signed, names, creq, body):
    scope = f"{DS}/{REGION}/{service}/aws4_request"
    sts = f"AWS4-HMAC-SHA256\n{AMZ}\n{scope}\n{sha(creq)}"
    sig = hmac.new(signing_key(SECRET, DS, REGION, service), sts.encode(),
                   hashlib.sha256).hexdigest()
    auth = (f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, "
            f"SignedHeaders={names}, Signature={sig}")
    wire = "".join(f"{n}: {signed[n]}\r\n" for n in sorted(signed))
    wire += f"content-length: {len(body)}\r\n"
    wire += f"authorization: {auth}\r\n"
    target = wire_path + (f"?{canon_q}" if canon_q else "")
    return f"{method} {target} HTTP/1.1\r\n{wire}Connection: close\r\n\r\n{body}"


def expand_path(template, labels):
    out, i, n = "", 0, len(template)
    while i < n:
        if template[i] == "{":
            close = template.find("}", i)
            token = template[i + 1:close]
            out += uri_encode(labels.get(token, ""), False)
            i = close + 1
        else:
            out += template[i]
            i += 1
    return out


def canonical_query(params):
    enc = sorted((uri_encode(k, False), uri_encode(v, False)) for k, v in params.items())
    return "&".join(f"{k}={v}" for k, v in enc)


def form_body(action, version, pairs):
    """The query codec's form body: Action, Version, then members in order, each
    key/value url.quote'd and joined with '&'."""
    all_pairs = [("Action", action), ("Version", version)] + pairs
    return "&".join(f"{uri_encode(k, False)}={uri_encode(v, False)}" for k, v in all_pairs)


# --- the pinned operations ----------------------------------------------------

def cf_create_invalidation():
    root = Elem("InvalidationBatch").attr("xmlns", CF_NS)
    paths = root.child("Paths")
    paths.scalar("Quantity", "2")
    items = paths.child("Items")
    items.scalar("Path", "/img/a.png").scalar("Path", "/img/b.png")
    root.scalar("CallerReference", "ref-2021")
    body = dumps(root)
    return binding_sign(
        "cloudfront", regional_host("cloudfront"), "POST",
        "/2015-09-17/distribution/{DistributionId}/invalidation",
        {"DistributionId": "EDFDVBD6EXAMPLE"}, {}, body, "application/xml")


def cf_create_oai():
    root = Elem("CloudFrontOriginAccessIdentityConfig").attr("xmlns", CF_NS)
    root.scalar("CallerReference", "oai-2021").scalar("Comment", "my identity")
    body = dumps(root)
    return binding_sign(
        "cloudfront", regional_host("cloudfront"), "POST",
        "/2015-09-17/origin-access-identity/cloudfront",
        {}, {}, body, "application/xml")


def synth_put_thing():
    # Prefixed namespace root + an xmlAttribute + a flattened list.
    root = Elem("ns:Config").attr("xmlns:ns", "urn:svc").attr("Version", "2")
    root.scalar("Name", "gadget")
    root.scalar("Alias", "a1").scalar("Alias", "a2")
    body = dumps(root)
    return binding_sign(
        "svc", regional_host("svc"), "PUT", "/thing/{Id}",
        {"Id": "t 1"}, {}, body, "application/xml")


def sdb_get_attributes():
    body = form_body("GetAttributes", "2009-04-15", [
        ("DomainName", "My Domain"),
        ("ItemName", "Item42"),
        ("AttributeNames.1", "Color"),
        ("AttributeNames.2", "Size"),
        ("ConsistentRead", "true"),
    ])
    return query_sign("sdb", regional_host("sdb"), body)


def ec2_monitor_instances():
    body = form_body("MonitorInstances", "2014-09-01", [
        ("DryRun", "true"),
        ("InstanceId.1", "i-1111"),
        ("InstanceId.2", "i-2222"),
    ])
    return query_sign("ec2", regional_host("ec2"), body)


def sts_get_caller_identity():
    # Empty input: only the Action/Version pair.
    body = form_body("GetCallerIdentity", "2011-06-15", [])
    return query_sign("sts", regional_host("sts"), body)


def sts_get_session_token():
    # Optional scalars in model order; the MFA serial url-encodes (`:` / `/`).
    body = form_body("GetSessionToken", "2011-06-15", [
        ("DurationSeconds", "3600"),
        ("SerialNumber", "arn:aws:iam::123456789012:mfa/user"),
        ("TokenCode", "123456"),
        ("MinimumSessionTokenSize", "1024"),
    ])
    return query_sign("sts", regional_host("sts"), body)


# --- S3 (rest-xml, the generated-is-product service #356) ---------------------
#
# The four pinned S3 operations the generator emits *correctly* end to end under
# the v0 rest-xml emitter — a bucket op, a service-level listing, an object GET
# and an object PUT with a raw body — each signed by the S3 binding variant. They
# stand in for the ticket's named ops (GetObject / PutObject / ListObjectsV2 /
# CreateBucket), which the v0 emitter skips (DateTime / bool header + query
# bindings, optional httpPayload structs — see the generated file's skip block).
# The `{Key+}` object key carries a space and "/"s to exercise greedy-label
# encoding (keep "/", space -> %20), the S3-key case the hand-written aws.s3
# reference calls out (zaplang-io/zap#335).

S3_BUCKET = "my-bucket"
S3_KEY = "photos/2024/my object.jpg"
S3_UPLOAD_ID = "abc123XYZ"


def s3_head_bucket():
    # HEAD /{Bucket} — a bucket op: no query, no body, no member headers.
    return s3_binding_sign(
        "HEAD", "/{Bucket}", {"Bucket": S3_BUCKET}, {}, {}, {}, "", "")


def s3_list_buckets():
    # GET / — a service-level listing; httpQuery scalars (sorted canonically).
    return s3_binding_sign(
        "GET", "/", {}, {},
        {"max-buckets": "100", "prefix": "team-"}, {}, "", "")


def s3_list_parts():
    # GET /{Bucket}/{Key+} — an object GET: greedy key + httpQuery (an int and a
    # required string).
    return s3_binding_sign(
        "GET", "/{Bucket}/{Key+}", {"Bucket": S3_BUCKET}, {"Key": S3_KEY},
        {"uploadId": S3_UPLOAD_ID, "max-parts": "50"}, {}, "", "")


def s3_upload_part():
    # PUT /{Bucket}/{Key+} — an object PUT: greedy key + httpQuery + a raw
    # httpPayload body (application/octet-stream), the PutObject-shaped case.
    return s3_binding_sign(
        "PUT", "/{Bucket}/{Key+}", {"Bucket": S3_BUCKET}, {"Key": S3_KEY},
        {"partNumber": "1", "uploadId": S3_UPLOAD_ID},
        {}, "hello part contents", "application/octet-stream")


FIXTURES = {
    "cloudfront_create_invalidation": cf_create_invalidation,
    "cloudfront_create_oai": cf_create_oai,
    "restxml_synth_put_thing": synth_put_thing,
    "sdb_get_attributes": sdb_get_attributes,
    "ec2_monitor_instances": ec2_monitor_instances,
    "sts_get_caller_identity": sts_get_caller_identity,
    "sts_get_session_token": sts_get_session_token,
    "s3_head_bucket": s3_head_bucket,
    "s3_list_buckets": s3_list_buckets,
    "s3_list_parts": s3_list_parts,
    "s3_upload_part": s3_upload_part,
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
                f"MISMATCH {name}\n--- computed ---\n{computed!r}\n"
                f"--- expected ---\n{expected!r}\n"
            )
            failed = True
        else:
            print(f"ok {name} — XML-family byte-diff vector verified")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
