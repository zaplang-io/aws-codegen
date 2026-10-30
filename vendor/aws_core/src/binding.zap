# aws.binding — the protocol-agnostic HTTP binding layer for the Zap AWS SDK.
#
# AWS's "REST" protocols (rest-json / restJson1 here, rest-xml #352 next, and the
# query/ec2 protocols after) all share one idea: an operation's input/output
# members are placed at HTTP *locations* chosen by Smithy location traits —
#   * httpLabel     → a `{Name}` / `{Name+}` segment of the URI path template,
#   * httpQuery     → a query-string parameter,
#   * httpHeader    → a single request/response header,
#   * httpPrefixHeaders → a string→string map rendered as a group of headers
#                    sharing a common name prefix (e.g. S3 `x-amz-meta-*`),
#   * httpPayload   → one member carried as the raw body, OR, when no member is
#                    marked, all remaining "document" members serialized into the
#                    body.
# Only the *document body* differs between protocols (JSON vs XML vs form). So
# this file owns the location mechanism and is deliberately format-agnostic: the
# serialized body bytes are handed in by the codec (aws.restjson plugs a JSON
# `@derive(Json)` serializer; aws.rest_xml #352 will plug an XML one), and
# nothing here mentions a wire format. That keeps the binding layer reusable
# across protocols exactly as the ticket (zaplang-io/zap#345) requires.
#
# Depends on aws.core (bundled ahead of this file; see FRICTION.md #1 on why
# there is no `import aws.core` yet). The binding builds a core `Request` that
# the core SigV4 signer consumes unchanged — the canonical request the signer
# derives from a binding-produced request is byte-identical to a hand-built one,
# so the pinned SigV4 vectors are unaffected.

import core
import crypto
import url

# ---------------------------------------------------------------------------
# Payload kinds
# ---------------------------------------------------------------------------

# How a binding's body was produced. Descriptive metadata the codec sets so a
# caller (or a debugger / trace) can tell document bodies from raw ones:
#   * Empty    — no request body (GET/DELETE with everything in URI/headers);
#   * Document — all "document" members serialized by the codec's document
#     serializer (JSON for rest-json), `content_type` the protocol media type;
#   * Raw      — one member bound with httpPayload, carried verbatim, with its
#     own `content_type`.
# `binding_request` treats every kind the same (it signs `body` as-is); the kind
# exists so the protocol framing decision stays explicit and inspectable.
enum PayloadKind:
    Empty
    Document
    Raw

# ---------------------------------------------------------------------------
# The binding plan
# ---------------------------------------------------------------------------

# A declarative map of one operation's input members to their HTTP locations,
# built by per-operation code and consumed by `binding_request` to assemble a
# signed-ready core `Request`. Everything here is protocol-agnostic: `body` is
# whatever bytes the codec serialized (document or raw payload) and `content_type`
# is set by the codec, so this struct never encodes JSON-vs-XML knowledge.
#
#   * `labels` / `greedy_labels` fill the `{Name}` / `{Name+}` segments of
#     `path_template`. A non-greedy label percent-encodes "/" (it is one path
#     segment); a greedy label keeps "/" (it spans segments, e.g. an S3 key).
#   * `query` is the decoded query parameters (the SigV4 signer percent-encodes
#     and sorts them, matching botocore).
#   * `headers` are member-bound headers (lowercase names). `prefix_header_prefix`
#     + `prefix_headers` render httpPrefixHeaders: each entry becomes a header
#     named `prefix + suffix`.
struct HttpBinding:
    str method
    str path_template
    dict[str, str] labels
    dict[str, str] greedy_labels
    dict[str, str] query
    dict[str, str] headers
    str prefix_header_prefix
    dict[str, str] prefix_headers
    PayloadKind payload_kind
    str body
    str content_type

# An empty binding for `method` over `path_template` (e.g. "/{Bucket}/{Key+}").
# Per-operation code fills the maps and sets a payload with `with_payload`
# (usually via the codec's `rest_json_document` / `rest_json_raw_payload`).
def new_binding(str method, str path_template) -> HttpBinding:
    return HttpBinding(
        method=method,
        path_template=path_template,
        labels={},
        greedy_labels={},
        query={},
        headers={},
        prefix_header_prefix="",
        prefix_headers={},
        payload_kind=PayloadKind.Empty,
        body="",
        content_type="",
    )

# Return a copy of `b` carrying a serialized body. `kind` is PayloadKind.Document
# or PayloadKind.Raw; `content_type` is the protocol's document media type or the
# raw member's media type. Kept format-agnostic — the codec chooses `content_type`.
def with_payload(
    HttpBinding b,
    PayloadKind kind,
    str body,
    str content_type,
) -> HttpBinding:
    return HttpBinding(
        method=b.method,
        path_template=b.path_template,
        labels=b.labels,
        greedy_labels=b.greedy_labels,
        query=b.query,
        headers=b.headers,
        prefix_header_prefix=b.prefix_header_prefix,
        prefix_headers=b.prefix_headers,
        payload_kind=kind,
        body=body,
        content_type=content_type,
    )

# ---------------------------------------------------------------------------
# URI label expansion (httpLabel)
# ---------------------------------------------------------------------------

# Percent-encode one URI label value. A non-greedy label is a single path
# segment, so "/" is encoded (`url.quote` → %2F); a greedy label ({Name+}) spans
# segments, so "/" is preserved (`url.quote_path`). Everything else is RFC-3986
# percent-encoded either way (zaplang-io/zap#335).
def encode_label(str value, bool greedy) -> str:
    if greedy:
        return url.quote_path(value)
    return url.quote(value)

# Expand a URI path template: every "{Name}" is replaced by the non-greedy label
# `labels[Name]` and every "{Name+}" by the greedy label `greedy[Name]`, each
# percent-encoded by `encode_label`. A single left-to-right scan (no regex, so
# the output is deterministic); an unmatched "{" is emitted literally. A label
# named in the template but absent from the maps expands to "".
def expand_path(str template, dict[str, str] labels, dict[str, str] greedy) -> str:
    auto out = ""
    auto i = 0
    auto n = len(template)
    while i < n:
        auto ch = template[i:i + 1]
        if ch == "{":
            auto close = template[i:n].find("}")
            if close < 0:
                out = out + template[i:n]
                i = n
            else:
                auto token = template[i + 1:i + close]
                if token.endswith("+"):
                    auto name = token[0:len(token) - 1]
                    Optional[str] v = greedy.get(name)
                    out = out + encode_label(v.unwrap_or(""), True)
                else:
                    Optional[str] v = labels.get(token)
                    out = out + encode_label(v.unwrap_or(""), False)
                i = i + close + 1
        else:
            out = out + ch
            i = i + 1
    return out

# ---------------------------------------------------------------------------
# Header assembly (httpHeader + httpPrefixHeaders)
# ---------------------------------------------------------------------------

# Render httpPrefixHeaders: each `suffix → value` entry becomes a header named
# `prefix + suffix` (lowercased). Returns a fresh dict. The inverse of
# `collect_prefix_headers` on the response side.
def render_prefix_headers(str prefix, dict[str, str] entries) -> dict[str, str]:
    dict[str, str] out = {}
    for k in entries.keys():
        Optional[str] v = entries.get(k)
        out[(prefix + k).lower()] = v.unwrap_or("")
    return out

# The full set of headers to sign for a binding: the transport/signing headers
# (host, x-amz-date, x-amz-content-sha256) plus the member-bound headers, the
# rendered prefix-headers, and Content-Type when the binding sets one. All names
# are lowercased; the SigV4 signer sorts and trims them, so insertion order here
# is irrelevant to the signature.
def binding_headers(
    HttpBinding b,
    str host,
    str amz_date,
    str payload_sha,
) -> dict[str, str]:
    dict[str, str] h = {}
    h["host"] = host
    h["x-amz-date"] = amz_date
    h["x-amz-content-sha256"] = payload_sha
    for name in b.headers.keys():
        Optional[str] v = b.headers.get(name)
        h[name.lower()] = v.unwrap_or("")
    if len(b.prefix_header_prefix) > 0:
        auto pfx = render_prefix_headers(b.prefix_header_prefix, b.prefix_headers)
        for name in pfx.keys():
            Optional[str] pv = pfx.get(name)
            h[name] = pv.unwrap_or("")
    if len(b.content_type) > 0:
        h["content-type"] = b.content_type
    return h

# ---------------------------------------------------------------------------
# Request assembly
# ---------------------------------------------------------------------------

# Assemble a signed-ready core `Request` from a binding. The URI is the expanded
# path template — already percent-encoded per label (see `expand_path`) — the
# query is the binding's decoded query dict (the signer percent-encodes it), the
# headers come from `binding_headers`, and the body is the binding's serialized
# payload. x-amz-content-sha256 is set to SHA-256 of that body.
#
# NOTE on the path contract: unlike core's own `Request` producers (aws.s3 /
# aws.dynamodb), whose `req.path` is the DECODED path that `sign_request` then
# percent-encodes, a binding `Request` carries the ALREADY-encoded wire path,
# because the binding owns per-label encoding (a non-greedy label must encode
# "/" as %2F, which core's uniform `quote_path` cannot do). Sign it with
# `binding_sign` (below), NOT core's `sign_request`, so the path is not encoded
# twice.
def binding_request(
    HttpBinding b,
    str service,
    str region,
    str host,
    str amz_date,
) -> core.Request:
    auto path = expand_path(b.path_template, b.labels, b.greedy_labels)
    auto sha = core.payload_hash(b.body)
    auto headers = binding_headers(b, host, amz_date, sha)
    return core.Request(
        method=b.method,
        service=service,
        region=region,
        host=host,
        path=path,
        query=b.query.copy(),
        headers=headers,
        body=b.body,
    )

# The SigV4 CanonicalURI for an ALREADY wire-encoded path (the binding path
# contract). AWS double-encodes the canonical URI for every service except S3
# (which disables path normalization), so non-S3 gets one more `url.quote_path`
# pass over the wire path while S3 uses the wire path verbatim. This mirrors
# core's `canonical_uri`, but without the first encode pass that core applies to
# a decoded path — here the first pass already happened in `expand_path`.
def canonical_uri_encoded(str wire_path_str, str service) -> str:
    if service == "s3":
        return wire_path_str
    return url.quote_path(wire_path_str)

# Sign a binding `Request` whose `path` is the already-encoded wire path, and
# return ready-to-send HTTP/1.1 text. This is `core.sign_request` with exactly
# one difference — the path is treated as pre-encoded (canonical URI via
# `canonical_uri_encoded`, wire target = `req.path` verbatim) — so it reuses
# every proven SigV4 primitive (signing_key / canonical_request / string_to_sign
# / sign / authorization_header) and produces byte-identical signatures for an
# identical canonical request. The pinned SigV4 vectors sign through
# `core.sign_request` and are untouched by this function.
def binding_sign(
    core.Credentials creds,
    core.Request req,
    str amz_date,
    str date_stamp,
) -> str:
    auto to_sign = req.headers.copy()
    if creds.has_session:
        to_sign["x-amz-security-token"] = creds.session_token

    auto payload_sha = crypto.sha256(req.body)
    Optional[str] psha = to_sign.get("x-amz-content-sha256")
    payload_sha = psha.unwrap_or(payload_sha)

    auto canon_uri_str = canonical_uri_encoded(req.path, req.service)
    auto canon_q = url.canonical_query(req.query)
    auto canon = core.canonical_headers(to_sign)
    auto shead = core.signed_headers(to_sign)
    auto creq = core.canonical_request(
        req.method,
        canon_uri_str,
        canon_q,
        canon,
        shead,
        payload_sha,
    )
    auto cred_scope = core.credential_scope(date_stamp, req.region, req.service)
    auto sts = core.string_to_sign(amz_date, cred_scope, creq)
    auto key = core.signing_key(creds.secret_key, date_stamp, req.region, req.service)
    auto signature = core.sign(key, sts)
    auto auth = core.authorization_header(
        creds.access_key,
        cred_scope,
        shead,
        signature,
    )

    auto headers_block = core.wire_headers(to_sign) + "content-length: " + core.content_length(req.body) + "\r\n" + "authorization: " + auth + "\r\n"
    auto target = req.path
    if len(canon_q) > 0:
        target = target + "?" + canon_q
    return core.http_request_text(req.method, target, headers_block, req.body)

# ---------------------------------------------------------------------------
# Response binding (protocol-agnostic)
# ---------------------------------------------------------------------------

# A member bound to a response header (httpHeader), or none when absent. Matched
# case-insensitively against the parsed (lowercased) header map.
def bound_header(core.Response resp, str name) -> Optional[str]:
    return resp.headers.get(name.lower())

# Collect httpPrefixHeaders from a response: every header whose (lowercased) name
# starts with `prefix`, keyed by the suffix after the prefix. The inverse of
# `render_prefix_headers`.
def collect_prefix_headers(core.Response resp, str prefix) -> dict[str, str]:
    dict[str, str] out = {}
    auto p = prefix.lower()
    for name in resp.headers.keys():
        if name.startswith(p):
            Optional[str] v = resp.headers.get(name)
            out[name[len(p):len(name)]] = v.unwrap_or("")
    return out

# The HTTP status code bound to an output member (httpResponseCode).
def bound_status(core.Response resp) -> int64:
    return resp.status
