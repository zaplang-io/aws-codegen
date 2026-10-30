# aws.restjson — the rest-json (restJson1) codec.
#
# rest-json is AWS's REST protocol with a JSON document body: API Gateway,
# Lambda, MediaConvert, Glacier, Polly and many others speak it. It is the
# protocol-agnostic HTTP binding layer (aws.binding) with a JSON document
# serializer bolted on:
#   * request  — build an `HttpBinding` (URI labels, query, headers,
#     prefix-headers), attach a JSON document body (the operation's document
#     members, serialized with `@derive(Json).to_json()`) or a raw httpPayload
#     member, assemble a core `Request`, and SigV4-sign it;
#   * response — status + headers map to output members via the binding helpers
#     (`bound_status` / `bound_header` / `collect_prefix_headers`), and the JSON
#     body carries the remaining document members (decoded at the call site with
#     `@derive(Json)`'s `from_json`);
#   * errors   — the restJson1 error shape: the code from the `x-amzn-errortype`
#     header or the body's `__type`/`code`, the message from `message`/`Message`.
#
# The JSON document bytes are produced by `@derive(Json)` (zaplang-io/zap#100),
# so a per-operation client models its document members as a `@derive(Json)`
# struct and hands `doc.to_json()` here — the binding layer and this codec never
# parse or build JSON object structure themselves. Swapping the protocol is
# swapping the serializer, not this plumbing: aws.rest_xml (#352) reuses
# aws.binding with an XML document serializer and leaves everything else alone.
#
# NOTE on #346: the `@json` field hooks (DateTime→epoch/iso8601, bytes→base64,
# open-enum) are not yet in the toolchain `:latest` (PR #389 is in review). Until
# they land, a document struct carries already-formatted scalar members, and the
# `json_timestamp_*` / `json_blob` helpers below produce the AWS JSON value
# encodings for timestamp/blob members. When #346 merges, those encodings are
# generated inline by `@derive(Json)` and the helpers become optional — no change
# to the binding layer or this codec.
#
# Depends on aws.core + aws.binding (bundled ahead of this file).

import binding
import core
import base64
import datetime

# ---------------------------------------------------------------------------
# Content type
# ---------------------------------------------------------------------------

# The restJson1 document media type. Sent as Content-Type for a JSON document
# body (not for a raw httpPayload member, which carries its own media type).
def rest_json_content_type() -> str:
    return "application/json"

# ---------------------------------------------------------------------------
# Request: attach the body to a binding
# ---------------------------------------------------------------------------

# Attach a serialized JSON document as the request body and set
# Content-Type: application/json. `document` is the compact JSON the caller
# produced with `@derive(Json).to_json()` over the operation's document members
# (an empty object "{}" when the operation has no document members). This is the
# only place rest-json commits to JSON — the binding layer stays format-agnostic.
def rest_json_document(binding.HttpBinding b, str document) -> binding.HttpBinding:
    return binding.with_payload(
        b,
        binding.PayloadKind.Document,
        document,
        rest_json_content_type(),
    )

# Bind one member as the raw request body (httpPayload), carried verbatim with
# its own media type (e.g. "application/octet-stream" for a blob, "text/plain"
# for a string). No JSON wrapping — the member's bytes ARE the body.
def rest_json_raw_payload(
    binding.HttpBinding b,
    str raw,
    str content_type,
) -> binding.HttpBinding:
    return binding.with_payload(b, binding.PayloadKind.Raw, raw, content_type)

# ---------------------------------------------------------------------------
# Request: build + sign
# ---------------------------------------------------------------------------

# Assemble and SigV4-sign a rest-json request from a binding at explicit signing
# timestamps, returning ready-to-send HTTP/1.1 text. Resolves the URI labels and
# query, assembles the headers (including the JSON Content-Type), and signs via
# the core signer — whose canonicalization is unchanged, so the pinned SigV4
# vectors are unaffected.
def rest_json_sign(
    core.Credentials creds,
    binding.HttpBinding b,
    str service,
    str region,
    str host,
    str amz_date,
    str date_stamp,
) -> str:
    auto req = binding.binding_request(b, service, region, host, amz_date)
    return binding.binding_sign(creds, req, amz_date, date_stamp)

# Build + sign a rest-json request using the current UTC time (the live path).
def rest_json_request(
    core.Credentials creds,
    binding.HttpBinding b,
    str service,
    str region,
    str host,
) -> str:
    auto t = core.signing_time_now()
    return rest_json_sign(creds, b, service, region, host, t.amz_date, t.date_stamp)

# ---------------------------------------------------------------------------
# Response: body + error dispatch
# ---------------------------------------------------------------------------

# The JSON document body of a response. The output's document members live here;
# decode them at the call site with the typed `Output.from_json(rest_json_body(
# resp))`. Header/status-bound members come from `bound_header` / `bound_status`
# / `collect_prefix_headers` (aws.binding) instead.
def rest_json_body(core.Response resp) -> str:
    return resp.body

# Normalize a restJson1 error code to the bare shape name. AWS decorates it two
# ways: the `x-amzn-errortype` header may append a ":url" location suffix
# ("FooError:http://..."), and a body `__type` may carry a "namespace#Name"
# prefix ("com.amazonaws.foo#FooError"). Strip the "#" prefix, then the ":"
# suffix.
def sanitize_error_code(str code) -> str:
    auto c = code
    auto hash = c.find("#")
    if hash >= 0:
        c = c[hash + 1:len(c)]
    auto colon = c.find(":")
    if colon >= 0:
        c = c[0:colon]
    return c

# The restJson1 error code for a response: the `x-amzn-errortype` header if
# present, else the body's `__type`, else its `code`, normalized to the bare
# shape name. "" when none is present.
def rest_json_error_code(core.Response resp) -> str:
    auto code = ""
    Optional[str] h = binding.bound_header(resp, "x-amzn-errortype")
    code = h.unwrap_or(code)
    if len(code) == 0:
        Optional[str] jt = core.json_string_field(resp.body, "__type")
        code = jt.unwrap_or(code)
    if len(code) == 0:
        Optional[str] jc = core.json_string_field(resp.body, "code")
        code = jc.unwrap_or(code)
    return sanitize_error_code(code)

# Dispatch a response to a typed-ish AwsError, or none on 2xx success. The code
# comes from `rest_json_error_code`; the message from the body's `message` or
# `Message` field. The per-service modeled-exception registry (retryable flags,
# member fields) is future work — this is the shape error dispatch produces now,
# and it matches core's `AwsError` so retry/classification code is shared.
def rest_json_error(core.Response resp) -> Optional[core.AwsError]:
    if core.is_success(resp.status):
        return Optional.None
    auto code = rest_json_error_code(resp)
    auto message = ""
    Optional[str] m_lower = core.json_string_field(resp.body, "message")
    message = m_lower.unwrap_or(message)
    Optional[str] m_upper = core.json_string_field(resp.body, "Message")
    message = m_upper.unwrap_or(message)
    return Optional.Some(core.AwsError(code=code, message=message, status=resp.status))

# ---------------------------------------------------------------------------
# AWS scalar JSON value encodings (the #346 @json field hooks, as helpers)
# ---------------------------------------------------------------------------
#
# restJson1 encodes a few member types specially. Once zaplang-io/zap#346 lands,
# `@derive(Json)` emits these inline for annotated fields; until then (and for
# members formatted outside a derived struct) these produce the same bytes.

# A timestamp as a JSON number of Unix epoch SECONDS — the restJson1 default
# timestamp encoding (`@json(timestamp="epoch")`).
def json_timestamp_epoch(DateTime dt) -> str:
    return str(datetime.to_timestamp(dt))

# A timestamp as a JSON string in ISO-8601 date-time form
# (`@json(timestamp="iso8601")`), e.g. "2015-08-30T12:36:00Z".
def json_timestamp_iso8601(DateTime dt) -> str:
    return "\"" + datetime.strftime(dt, "%Y-%m-%dT%H:%M:%SZ") + "\""

# A blob member as a base64 JSON string (standard alphabet, padded) — the
# restJson1 blob encoding. Round-trips with `base64.decode`.
def json_blob(bytes b) -> str:
    return "\"" + base64.encode(b) + "\""
