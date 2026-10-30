# aws.cbor — the smithy-rpc-v2-cbor protocol codec (zaplang-io/zap#428, part 1).
#
# smithy-rpc-v2-cbor is AWS's newest RPC protocol: an operation is a POST to
#   /service/{ServiceName}/operation/{OperationName}
# whose body is the operation input serialized as a CBOR (RFC 8949) data item,
# with `smithy-protocol: rpc-v2-cbor`, `Accept: application/cbor`, and (when the
# body is non-empty) `Content-Type: application/cbor`. 25 services currently
# excluded from the aws-codegen manifest speak it (CloudWatch moved query→cbor
# upstream, Translate, and others). It is the sixth protocol, alongside awsJson
# 1.0/1.1, rest-json, rest-xml, query and ec2.
#
# This module is the aws-core FOUNDATION half of #428 — the wire codec + request
# framing + response/error decode + a byte-diff oracle. It is protocol-agnostic
# in the same sense aws.query / aws.awsjson are: it owns the CBOR wire format and
# the rpc-v2 framing, and the CALLER supplies the value model (member names and
# shapes) exactly as it builds query parameters or an awsJson body. Driving it
# from a service model — the aws-codegen emitter + the manifest entries for the
# 25 cbor services — is a DEFERRED follow-up queued behind the aws-codegen lane;
# nothing here touches the generator or models/manifest.json.
#
# CANONICAL CBOR. The encoding mirrors botocore's RpcV2CBORSerializer exactly, so
# the body bytes are the byte-diff oracle the generated emitter will be pinned
# against (see tools/verify_vectors.py `cbor_codec` + tests/expected/
# cbor_codec.expected). The rules smithy requires: definite-length encoding for
# every string/blob/list/map; struct members serialized as a map keyed by the
# (text-string) member name in MODEL order (botocore does NOT sort keys); and
# absent/null struct members omitted rather than encoded as null — the caller
# builds the map for present members only, like botocore's `{k: v for ... if v}`.
# Integers pick the shortest of the 1/2/3/5/9-byte forms; timestamps are CBOR
# tag 1 over integer epoch-seconds; floats are IEEE-754 (major 7, ai 27 for a
# 64-bit double, ai 26 for a 32-bit float), with inf/-inf/NaN as the half-float
# forms botocore emits. Event-stream framing is out of scope (excluded).
#
# SIGNING. A cbor request signs byte-identically through the SAME SigV4
# primitives the other codecs use: `cbor_sign` is `core.sign_request` over a
# bytes body (the pattern `binding.binding_sign` already established for REST),
# reusing core.canonical_headers / canonical_request / string_to_sign /
# signing_key / sign / authorization_header unchanged. The content hash is
# SHA-256 of the CBOR body (crypto.sha256 accepts bytes), carried in
# x-amz-content-sha256, so the pinned SigV4 vectors are untouched.
#
# Depends on aws.core (bundled ahead of this file; see FRICTION.md #1 on why
# there is no `import aws.core`). Additive only — no signing/endpoint/existing
# codec path changes.

import core
import crypto
import hex
import math

# ---------------------------------------------------------------------------
# The CBOR value model
# ---------------------------------------------------------------------------

# One CBOR data item. `Map` carries parallel key/value lists (text-string keys,
# insertion order = wire order) — structures ARE maps keyed by member name, and a
# modeled map ships as the same shape. The caller builds the tree with the
# constructor helpers below; `cbor_encode` serializes it to canonical CBOR bytes.
enum CborValue:
    Int(int64 v)
    Bool(bool b)
    Null
    Text(str s)
    Blob(bytes b)
    Double(float64 f)
    Single(float64 f)
    Timestamp(int64 epoch)
    List(list[CborValue] items)
    Map(list[str] keys, list[CborValue] vals)

# Constructor helpers — a readable builder surface mirroring aws.query's
# query_scalar / query_list. `cbor_int` picks the unsigned/negative major type at
# encode time, so the caller just passes a signed int64.
def cbor_int(int64 v) -> CborValue:
    return CborValue.Int(v)

def cbor_bool(bool b) -> CborValue:
    return CborValue.Bool(b)

def cbor_null() -> CborValue:
    return CborValue.Null

def cbor_text(str s) -> CborValue:
    return CborValue.Text(s)

def cbor_blob(bytes b) -> CborValue:
    return CborValue.Blob(b)

# A 64-bit double (the AWS `double` shape) — major 7, additional info 27.
def cbor_double(float64 f) -> CborValue:
    return CborValue.Double(f)

# A 32-bit float (the AWS `float` shape) — major 7, additional info 26.
def cbor_single(float64 f) -> CborValue:
    return CborValue.Single(f)

# A timestamp as integer Unix epoch-seconds (the rpc-v2-cbor `unixtimestamp`
# format) — CBOR tag 1 over an unsigned integer.
def cbor_timestamp(int64 epoch) -> CborValue:
    return CborValue.Timestamp(epoch)

def cbor_list(list[CborValue] items) -> CborValue:
    return CborValue.List(items)

# A map / structure: `keys[i]` → `vals[i]`, in order. Build it for PRESENT
# members only — rpc-v2-cbor omits absent/null struct members.
def cbor_map(list[str] keys, list[CborValue] vals) -> CborValue:
    return CborValue.Map(keys, vals)

# ---------------------------------------------------------------------------
# Byte accumulation (bytes has no `+`, so encode into a list[int64] then finish)
# ---------------------------------------------------------------------------

# The CBOR major types (RFC 8949 §3), spelled out so the encoder reads like the
# spec: unsigned int, negative int, byte string, text string, array, map, tag,
# and the float/simple space.
def major_uint() -> int64:
    return 0

def major_nint() -> int64:
    return 1

def major_blob() -> int64:
    return 2

def major_text() -> int64:
    return 3

def major_list() -> int64:
    return 4

def major_map() -> int64:
    return 5

def major_tag() -> int64:
    return 6

def major_simple() -> int64:
    return 7

# Append the `k` low-order bytes of `n` in big-endian order.
def append_be(list[int64] out, int64 n, int64 k) -> list[int64]:
    auto i = k - 1
    while i >= 0:
        out.append(n >> 8 * i & 255)
        i = i - 1
    return out

# Append a CBOR "initial byte + argument" head for `(major, n)`, choosing the
# shortest definite-length form: inline (n<24), 1, 2, 4 or 8 following bytes.
def encode_head(list[int64] out, int64 major, int64 n) -> list[int64]:
    auto base = major << 5
    if n < 24:
        out.append(base + n)
    elif n < 256:
        out.append(base + 24)
        out.append(n)
    elif n < 65536:
        out.append(base + 25)
        out = append_be(out, n, 2)
    elif n < 4294967296:
        out.append(base + 26)
        out = append_be(out, n, 4)
    else:
        out.append(base + 27)
        out = append_be(out, n, 8)
    return out

# ---------------------------------------------------------------------------
# IEEE-754 float encoding (no float<->bits primitive, so pack by hand)
# ---------------------------------------------------------------------------
#
# struct.pack(">d"/">f") equivalents, built from integer/float arithmetic. Zap's
# float64 math is IEEE double precision, so for every exactly-representable value
# (what the pinned vectors use) these produce the same bytes as botocore; the
# general algorithm follows IEEE round-to-nearest for other finite values.

# 2 raised to an integer power, as a float64.
def pow2f(int64 k) -> float64:
    return math.pow(2.0, float64(k))

# Append the half-float (major 7, ai 25) form botocore uses for the special
# numbers: +inf 0x7C00, -inf 0xFC00, NaN 0x7E00.
def append_special(list[int64] out, float64 d) -> list[int64]:
    out.append((major_simple() << 5) + 25)
    if math.isnan(d):
        out.append(0x7E)
        out.append(0x00)
    elif d > 0.0:
        out.append(0x7C)
        out.append(0x00)
    else:
        out.append(0xFC)
        out.append(0x00)
    return out

# Append the 8 bytes of a double from its decomposed sign / biased exponent (11
# bits) / mantissa (52 bits).
def append_double_bits(
    list[int64] out,
    int64 sign,
    int64 biased,
    int64 mant,
) -> list[int64]:
    out.append(sign << 7 | biased >> 4)
    out.append((biased & 15) << 4 | mant >> 48)
    auto rest = mant & 281474976710655
    out.append(rest >> 40 & 255)
    out.append(rest >> 32 & 255)
    out.append(rest >> 24 & 255)
    out.append(rest >> 16 & 255)
    out.append(rest >> 8 & 255)
    out.append(rest & 255)
    return out

# Encode a 64-bit double: 0xFB then 8 IEEE-754 bytes (specials as half-floats).
def encode_double(list[int64] out, float64 d) -> list[int64]:
    if math.isnan(d) or math.isinf(d):
        return append_special(out, d)
    out.append((major_simple() << 5) + 27)
    auto sign = 0
    auto x = d
    if x < 0.0:
        sign = 1
        x = 0.0 - x
    if x == 0.0:
        return append_double_bits(out, sign, 0, 0)
    auto e = int(math.floor(math.log2(x)))
    auto m = x * pow2f(0 - e)
    if m >= 2.0:
        e = e + 1
        m = x * pow2f(0 - e)
    elif m < 1.0:
        e = e - 1
        m = x * pow2f(0 - e)
    auto biased = e + 1023
    auto frac = m - 1.0
    auto mant = int(frac * pow2f(52) + 0.5)
    if mant == 4503599627370496:
        mant = 0
        biased = biased + 1
    return append_double_bits(out, sign, biased, mant)

# Append the 4 bytes of a single-precision float from its decomposed sign /
# biased exponent (8 bits) / mantissa (23 bits).
def append_single_bits(
    list[int64] out,
    int64 sign,
    int64 biased,
    int64 mant,
) -> list[int64]:
    out.append(sign << 7 | biased >> 1)
    out.append((biased & 1) << 7 | mant >> 16)
    out.append(mant >> 8 & 255)
    out.append(mant & 255)
    return out

# Encode a 32-bit float: 0xFA then 4 IEEE-754 bytes (specials as half-floats).
def encode_single(list[int64] out, float64 d) -> list[int64]:
    if math.isnan(d) or math.isinf(d):
        return append_special(out, d)
    out.append((major_simple() << 5) + 26)
    auto sign = 0
    auto x = d
    if x < 0.0:
        sign = 1
        x = 0.0 - x
    if x == 0.0:
        return append_single_bits(out, sign, 0, 0)
    auto e = int(math.floor(math.log2(x)))
    auto m = x * pow2f(0 - e)
    if m >= 2.0:
        e = e + 1
        m = x * pow2f(0 - e)
    elif m < 1.0:
        e = e - 1
        m = x * pow2f(0 - e)
    auto biased = e + 127
    auto frac = m - 1.0
    auto mant = int(frac * pow2f(23) + 0.5)
    if mant == 8388608:
        mant = 0
        biased = biased + 1
    return append_single_bits(out, sign, biased, mant)

# ---------------------------------------------------------------------------
# The encoder
# ---------------------------------------------------------------------------

# Append the CBOR encoding of one value to the accumulator (recursive for
# list/map). Integers split on sign into major 0 (n) / major 1 (-1-n), matching
# botocore; a text string is UTF-8 with a major-3 head; a blob is a major-2 head
# over its raw bytes; a timestamp is tag 1 (0xC1) over the unsigned epoch.
def encode_into(list[int64] out, CborValue v) -> list[int64]:
    match v:
        case CborValue.Int(n):
            if n >= 0:
                out = encode_head(out, major_uint(), n)
            else:
                out = encode_head(out, major_nint(), 0 - 1 - n)
        case CborValue.Bool(b):
            if b:
                out.append((major_simple() << 5) + 21)
            else:
                out.append((major_simple() << 5) + 20)
        case CborValue.Null:
            out.append((major_simple() << 5) + 22)
        case CborValue.Text(s):
            auto tb = bytes(s)
            out = encode_head(out, major_text(), len(tb))
            auto i = 0
            while i < len(tb):
                out.append(tb[i])
                i = i + 1
        case CborValue.Blob(b):
            out = encode_head(out, major_blob(), len(b))
            auto j = 0
            while j < len(b):
                out.append(b[j])
                j = j + 1
        case CborValue.Double(f):
            out = encode_double(out, f)
        case CborValue.Single(f):
            out = encode_single(out, f)
        case CborValue.Timestamp(epoch):
            out.append((major_tag() << 5) + 1)
            out = encode_head(out, major_uint(), epoch)
        case CborValue.List(items):
            out = encode_head(out, major_list(), len(items))
            for it in items:
                out = encode_into(out, it)
        case CborValue.Map(keys, vals):
            out = encode_head(out, major_map(), len(keys))
            auto k = 0
            while k < len(keys):
                auto kb = bytes(keys[k])
                out = encode_head(out, major_text(), len(kb))
                auto p = 0
                while p < len(kb):
                    out.append(kb[p])
                    p = p + 1
                out = encode_into(out, vals[k])
                k = k + 1
    return out

# Serialize a value to canonical CBOR bytes — the oracle the aws-codegen emitter
# is byte-diffed against.
def cbor_encode(CborValue v) -> bytes:
    list[int64] out = []
    out = encode_into(out, v)
    return bytes(out)

# ---------------------------------------------------------------------------
# Request framing (the rpc-v2-cbor HTTP shape)
# ---------------------------------------------------------------------------

# The rpc-v2-cbor media type, used for Content-Type (when there is a body) and
# Accept.
def cbor_content_type() -> str:
    return "application/cbor"

# The request URI for an operation: /service/{ServiceName}/operation/{Operation}.
# `service_shape` is the Smithy service shape name (botocore's rpc-v2 targetPrefix),
# `op` the operation name — both caller-supplied, like every other codec here.
def cbor_uri(str service_shape, str op) -> str:
    return "/service/" + service_shape + "/operation/" + op

# The signed header set every rpc-v2-cbor request carries: host, the SigV4
# timestamp, the CBOR body hash, the `smithy-protocol: rpc-v2-cbor` selector,
# `Accept: application/cbor`, and — only when the body is non-empty, matching
# botocore — `Content-Type: application/cbor`. Names are lowercase (the core
# signer lowercases/sorts for canonicalization anyway).
def cbor_headers(str host, str body_sha, str amz_date, bool has_body) -> dict[str, str]:
    dict[str, str] h = {}
    h["accept"] = cbor_content_type()
    h["host"] = host
    h["smithy-protocol"] = "rpc-v2-cbor"
    h["x-amz-content-sha256"] = body_sha
    h["x-amz-date"] = amz_date
    if has_body:
        h["content-type"] = cbor_content_type()
    return h

# Build the unsigned aws.core Request for a cbor operation. `body` is the CBOR
# bytes; the Request carries an empty string body and the real body hash is
# pinned in x-amz-content-sha256, so `core.sign_request` signs the CBOR payload
# without needing the binary bytes in the (str-typed) Request. The wire body is
# assembled by `cbor_sign`.
def cbor_build_request(
    str service,
    str region,
    str host,
    str service_shape,
    str op,
    bytes body,
    str amz_date,
) -> core.Request:
    auto body_sha = crypto.sha256(body)
    auto has_body = len(body) > 0
    auto headers = cbor_headers(host, body_sha, amz_date, has_body)
    dict[str, str] query = {}
    return core.Request(
        method="POST",
        service=service,
        region=region,
        host=host,
        path=cbor_uri(service_shape, op),
        query=query,
        headers=headers,
        body="",
    )

# ---------------------------------------------------------------------------
# Signing — the SAME SigV4 primitives, over a bytes body
# ---------------------------------------------------------------------------
#
# `cbor_sign` is `core.sign_request` with one difference: the payload hash and
# content-length come from the CBOR `body` bytes rather than a str Request body.
# It reuses every core SigV4 primitive unchanged, so for identical inputs the
# canonical request → signature → authorization header are byte-identical to the
# generated/oracle path. The pinned SigV4 vectors sign through
# `core.sign_request` and are unaffected.

# Assemble the ASCII request head (request line + signed headers + content-length
# + authorization) as bytes, then append the binary CBOR body — returning the
# full ready-to-send HTTP/1.1 request bytes. `req.headers` must already carry the
# correct x-amz-content-sha256 (from `cbor_build_request`).
def cbor_sign(
    core.Credentials creds,
    core.Request req,
    bytes body,
    str amz_date,
    str date_stamp,
) -> bytes:
    auto to_sign = req.headers.copy()
    if creds.has_session:
        to_sign["x-amz-security-token"] = creds.session_token

    auto payload_sha = crypto.sha256(body)
    Optional[str] psha = to_sign.get("x-amz-content-sha256")
    payload_sha = psha.unwrap_or(payload_sha)

    auto canon_uri_str = core.canonical_uri(req.path, req.service)
    auto canon_q = core.canonical_query(req.query)
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

    auto target = core.wire_path(req.path)
    if len(canon_q) > 0:
        target = target + "?" + canon_q
    auto headers_block = core.wire_headers(to_sign) + "content-length: " + str(len(body)) + "\r\n" + "authorization: " + auth + "\r\n"
    auto head = req.method + " " + target + " HTTP/1.1\r\n" + headers_block + "Connection: close\r\n" + "\r\n"

    list[int64] out = []
    auto hb = bytes(head)
    auto i = 0
    while i < len(hb):
        out.append(hb[i])
        i = i + 1
    auto j = 0
    while j < len(body):
        out.append(body[j])
        j = j + 1
    return bytes(out)

# The SigV4 hex signature alone for a cbor request (mirrors
# `core.request_signature` / `presign_signature`) — the hex signature without
# assembling the wire bytes, for known-answer assertions.
def cbor_signature(
    core.Credentials creds,
    core.Request req,
    bytes body,
    str amz_date,
    str date_stamp,
) -> str:
    auto to_sign = req.headers.copy()
    if creds.has_session:
        to_sign["x-amz-security-token"] = creds.session_token
    auto payload_sha = crypto.sha256(body)
    Optional[str] psha = to_sign.get("x-amz-content-sha256")
    payload_sha = psha.unwrap_or(payload_sha)
    auto canon_uri_str = core.canonical_uri(req.path, req.service)
    auto canon_q = core.canonical_query(req.query)
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
    return core.sign(key, sts)

# ---------------------------------------------------------------------------
# Response decode
# ---------------------------------------------------------------------------

# One decode step: the value read and the index of the first byte after it. The
# decoder threads this (there is no in-place cursor mutation) through the
# recursive list/map reads.
struct Decoded:
    CborValue value
    int64 next

# Read `k` big-endian bytes of `b` starting at `pos` as an unsigned integer.
def read_be(bytes b, int64 pos, int64 k) -> int64:
    auto v = 0
    auto i = 0
    while i < k:
        v = v << 8 | b[pos + i]
        i = i + 1
    return v

# Read the CBOR argument for additional-info `ai` at `pos` (the byte right after
# the initial byte): the inline value (ai<24) or the 1/2/4/8 following bytes.
# Returns the value and the index after the argument.
def read_arg(bytes b, int64 pos, int64 ai) -> Decoded:
    if ai < 24:
        return Decoded(value=CborValue.Int(ai), next=pos)
    if ai == 24:
        return Decoded(value=CborValue.Int(b[pos]), next=pos + 1)
    if ai == 25:
        return Decoded(value=CborValue.Int(read_be(b, pos, 2)), next=pos + 2)
    if ai == 26:
        return Decoded(value=CborValue.Int(read_be(b, pos, 4)), next=pos + 4)
    return Decoded(value=CborValue.Int(read_be(b, pos, 8)), next=pos + 8)

# Read the raw int argument (not wrapped) at `pos` for `ai`.
def read_len(bytes b, int64 pos, int64 ai) -> Decoded:
    return read_arg(b, pos, ai)

# Reconstruct a float64 from 8 big-endian IEEE-754 bytes starting at `pos`.
def read_double(bytes b, int64 pos) -> float64:
    auto b0 = b[pos]
    auto b1 = b[pos + 1]
    auto sign = b0 >> 7
    auto biased = (b0 & 127) << 4 | b1 >> 4
    auto mant = (b1 & 15) << 48 | read_be(b, pos + 2, 6)
    if biased == 0:
        auto sub = float64(mant) * pow2f(0 - 1074)
        if sign == 1:
            return 0.0 - sub
        return sub
    auto value = (1.0 + float64(mant) * pow2f(0 - 52)) * pow2f(biased - 1023)
    if sign == 1:
        return 0.0 - value
    return value

# Reconstruct a float64 from 4 big-endian IEEE-754 (single) bytes at `pos`.
def read_single(bytes b, int64 pos) -> float64:
    auto raw = read_be(b, pos, 4)
    auto sign = raw >> 31 & 1
    auto biased = raw >> 23 & 255
    auto mant = raw & 8388607
    if biased == 0:
        auto sub = float64(mant) * pow2f(0 - 149)
        if sign == 1:
            return 0.0 - sub
        return sub
    auto value = (1.0 + float64(mant) * pow2f(0 - 23)) * pow2f(biased - 127)
    if sign == 1:
        return 0.0 - value
    return value

# Decode one CBOR data item at `pos`. Supports the rpc-v2-cbor value model:
# integers, byte/text strings, arrays, maps, tag-1 timestamps, bool/null, and
# 32/64-bit floats. Indefinite-length items and tags other than 1 are not part of
# the protocol surface and are not decoded (documented scope).
def decode_at(bytes b, int64 pos) -> Decoded:
    auto ib = b[pos]
    auto major = ib >> 5
    auto ai = ib & 31
    if major == 0:
        auto a = read_arg(b, pos + 1, ai)
        return a
    if major == 1:
        auto a = read_len(b, pos + 1, ai)
        match a.value:
            case CborValue.Int(n):
                return Decoded(value=CborValue.Int(0 - 1 - n), next=a.next)
            case _:
                return Decoded(value=CborValue.Int(0 - 1), next=a.next)
    if major == 2:
        auto a = read_len(b, pos + 1, ai)
        match a.value:
            case CborValue.Int(n):
                return Decoded(
                    value=CborValue.Blob(b[a.next:a.next + n]),
                    next=a.next + n,
                )
            case _:
                return Decoded(value=CborValue.Blob(bytes([])), next=a.next)
    if major == 3:
        auto a = read_len(b, pos + 1, ai)
        match a.value:
            case CborValue.Int(n):
                return Decoded(
                    value=CborValue.Text(str(b[a.next:a.next + n])),
                    next=a.next + n,
                )
            case _:
                return Decoded(value=CborValue.Text(""), next=a.next)
    if major == 4:
        auto a = read_len(b, pos + 1, ai)
        auto count = 0
        match a.value:
            case CborValue.Int(n):
                count = n
            case _:
                count = 0
        list[CborValue] items = []
        auto cur = a.next
        auto i = 0
        while i < count:
            auto d = decode_at(b, cur)
            items.append(d.value)
            cur = d.next
            i = i + 1
        return Decoded(value=CborValue.List(items), next=cur)
    if major == 5:
        auto a = read_len(b, pos + 1, ai)
        auto count = 0
        match a.value:
            case CborValue.Int(n):
                count = n
            case _:
                count = 0
        list[str] keys = []
        list[CborValue] vals = []
        auto cur = a.next
        auto i = 0
        while i < count:
            auto kd = decode_at(b, cur)
            auto key = ""
            match kd.value:
                case CborValue.Text(s):
                    key = s
                case _:
                    key = ""
            auto vd = decode_at(b, kd.next)
            keys.append(key)
            vals.append(vd.value)
            cur = vd.next
            i = i + 1
        return Decoded(value=CborValue.Map(keys, vals), next=cur)
    if major == 6:
        auto a = read_len(b, pos + 1, ai)
        auto inner = decode_at(b, a.next)
        match inner.value:
            case CborValue.Int(n):
                return Decoded(value=CborValue.Timestamp(n), next=inner.next)
            case _:
                return Decoded(value=inner.value, next=inner.next)
    if ai == 20:
        return Decoded(value=CborValue.Bool(False), next=pos + 1)
    if ai == 21:
        return Decoded(value=CborValue.Bool(True), next=pos + 1)
    if ai == 22:
        return Decoded(value=CborValue.Null, next=pos + 1)
    if ai == 26:
        return Decoded(value=CborValue.Single(read_single(b, pos + 1)), next=pos + 5)
    if ai == 27:
        return Decoded(value=CborValue.Double(read_double(b, pos + 1)), next=pos + 9)
    return Decoded(value=CborValue.Null, next=pos + 1)

# Decode a whole CBOR body into its value tree.
def cbor_decode(bytes b) -> CborValue:
    return decode_at(b, 0).value

# The value for `key` in a decoded map, or none when `v` is not a map or the key
# is absent.
def cbor_map_get(CborValue v, str key) -> Optional[CborValue]:
    match v:
        case CborValue.Map(keys, vals):
            auto i = 0
            while i < len(keys):
                if keys[i] == key:
                    return Optional.Some(vals[i])
                i = i + 1
            return Optional.None
        case _:
            return Optional.None

# The text of a CBOR value, or "" when it is not a text string.
def cbor_as_text(CborValue v) -> str:
    match v:
        case CborValue.Text(s):
            return s
        case _:
            return ""

# The integer of a CBOR value, or 0 when it is not an integer.
def cbor_as_int(CborValue v) -> int64:
    match v:
        case CborValue.Int(n):
            return n
        case _:
            return 0

# The boolean of a CBOR value, or false when it is not a bool.
def cbor_as_bool(CborValue v) -> bool:
    match v:
        case CborValue.Bool(b):
            return b
        case _:
            return False

# The epoch-seconds of a CBOR timestamp value, or 0 when it is not a timestamp.
def cbor_as_timestamp(CborValue v) -> int64:
    match v:
        case CborValue.Timestamp(epoch):
            return epoch
        case _:
            return 0

# The element count of a CBOR list value, or 0 when it is not a list. (These
# module-local accessors exist because a CONSUMER cannot `match` on a
# module-qualified variant pattern yet — see DECISIONS.md D-0006 — so callers read
# a decoded tree through these helpers rather than matching `CborValue` directly.)
def cbor_list_len(CborValue v) -> int64:
    match v:
        case CborValue.List(items):
            return len(items)
        case _:
            return 0

# The `i`-th element of a CBOR list value, or Null when out of range / not a list.
def cbor_list_at(CborValue v, int64 i) -> CborValue:
    match v:
        case CborValue.List(items):
            if i >= 0 and i < len(items):
                return items[i]
            return CborValue.Null
        case _:
            return CborValue.Null

# ---------------------------------------------------------------------------
# Error dispatch (the rpc-v2-cbor error shape)
# ---------------------------------------------------------------------------
#
# A CBOR response body is BINARY and is taken as `bytes`, not read off
# `core.Response.body` (a `str`): unlike JSON/XML/query, a CBOR body cannot
# round-trip through a str (`bytes(str)` is a UTF-8 ENCODE, not a reinterpret, so
# it would corrupt bytes >= 0x80), and there is no str→bytes reinterpret in the
# language. The deferred emitter/transport half (#428 part 2) hands the raw
# response body here as bytes; the status comes from the parsed `core.Response`.

# The error shape name a cbor fault carries: the body is a CBOR map with a
# `__type` member (namespaced like awsJson, e.g. "com.amazonaws.cloudwatch#..."),
# normalized to the bare shape name at the call site via `errors.error_code`.
# Returns "" when absent.
def cbor_error_type(bytes body) -> str:
    auto root = cbor_decode(body)
    Optional[CborValue] t = cbor_map_get(root, "__type")
    if t.is_some():
        return cbor_as_text(t.unwrap())
    return ""

# The error message a cbor fault carries: services use "message" or "Message".
def cbor_error_message(bytes body) -> str:
    auto root = cbor_decode(body)
    Optional[CborValue] lower = cbor_map_get(root, "message")
    if lower.is_some():
        return cbor_as_text(lower.unwrap())
    Optional[CborValue] upper = cbor_map_get(root, "Message")
    if upper.is_some():
        return cbor_as_text(upper.unwrap())
    return ""

# Dispatch a cbor fault (HTTP `status` + raw CBOR `body` bytes) to an AwsError,
# or none on a 2xx status — matching aws.core's `AwsError` so retry/classification
# is shared across protocols (like awsjson/query/restxml). The raw `__type` is
# surfaced as the code; normalize it to the bare shape name with
# `errors.error_code` for typed dispatch.
def cbor_error(int64 status, bytes body) -> Optional[core.AwsError]:
    if core.is_success(status):
        return Optional.None
    return Optional.Some(
        core.AwsError(
            code=cbor_error_type(body),
            message=cbor_error_message(body),
            status=status,
        ),
    )
