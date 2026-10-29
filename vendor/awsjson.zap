# aws.awsjson — the awsJson 1.0 / 1.1 protocol codec (D-0011 §2, zaplang-io/zap#344).
#
# awsJson is the RPC-style JSON protocol that DynamoDB, Kinesis, CloudWatch,
# SQS-JSON and many other services speak. Unlike rest-json (#345) nothing is
# bound to the URI, the query string, or individual headers: every operation is
# a POST to "/" whose entire input shape is one JSON object in the body, with the
# operation selected by the `X-Amz-Target: <prefix>.<Operation>` header and the
# protocol version pinned by the Content-Type (`application/x-amz-json-1.0` vs
# `-1.1`). This module is the protocol-agnostic half: it rides on aws.core's
# Request/Response model, SigV4 signer and HTTPS transport (bundled ahead of this
# file — see FRICTION.md #1 on why there is no `import aws.core`), and per-service
# modules (aws.dynamodb) hand it a serialized body + an operation name.
#
# REQUEST  — the caller serializes the operation's typed input shape with
#   `@derive(Json)` (`input.to_json()`) and passes the body here; `awsjson_request`
#   sets Content-Type + X-Amz-Target, posts to "/", and SigV4-signs via aws.core.
# RESPONSE — the caller parses the body back into the typed output shape with
#   `@derive(Json)` (`Output.from_json(resp.body)`); this module decides success
#   vs failure and, on failure, performs error dispatch.
# ERRORS   — awsJson carries the error shape name in the `__type` body field (and/
#   or the `X-Amzn-ErrorType` response header), often namespaced
#   ("com.amazonaws.dynamodb.v20120810#ResourceNotFoundException") or URL-suffixed
#   ("ResourceNotFoundException:http://..."); `awsjson_error` strips both forms to
#   the bare shape name and surfaces an aws.core.AwsError carrying code + message
#   + status, matching the error pattern aws.core already produces.
#
# @derive(Json) models the dynamic-key AttributeValue maps DynamoDB uses by hand
# (collections in derive are a follow-up), but flat/nested shapes — e.g.
# DescribeTable — ride the derive path end to end; see aws.dynamodb.

# ---------------------------------------------------------------------------
# Protocol configuration (per client)
# ---------------------------------------------------------------------------

# An awsJson client's protocol settings: the Content-Type that pins the wire
# version (1.0 vs 1.1), the X-Amz-Target JSON prefix (the service's API id, e.g.
# "DynamoDB_20120810"), and the SigV4 service name. A per-service module builds
# one of these once and threads it through every operation.
struct AwsJson:
    str content_type
    str target_prefix
    str service

# awsJson 1.0 client config (Content-Type application/x-amz-json-1.0).
def awsjson_1_0(str target_prefix, str service) -> AwsJson:
    return AwsJson(
        content_type="application/x-amz-json-1.0",
        target_prefix=target_prefix,
        service=service,
    )

# awsJson 1.1 client config (Content-Type application/x-amz-json-1.1).
def awsjson_1_1(str target_prefix, str service) -> AwsJson:
    return AwsJson(
        content_type="application/x-amz-json-1.1",
        target_prefix=target_prefix,
        service=service,
    )

# The X-Amz-Target header value for an operation: "<prefix>.<OperationName>"
# (e.g. "DynamoDB_20120810.GetItem").
def awsjson_target(AwsJson p, str op) -> str:
    return p.target_prefix + "." + op

# ---------------------------------------------------------------------------
# Request serialization
# ---------------------------------------------------------------------------

# The signed header set every awsJson operation shares: Content-Type (version),
# host, the payload hash, the SigV4 timestamp and the X-Amz-Target selector. The
# path is always "/" and there is no query string, so these headers plus the body
# are the whole request. Header names are lowercase (aws.core lowercases/sorts
# them for canonicalization anyway).
def awsjson_headers(
    AwsJson p,
    str host,
    str body_sha,
    str amz_date,
    str op,
) -> dict[str, str]:
    dict[str, str] h = {}
    h["content-type"] = p.content_type
    h["host"] = host
    h["x-amz-content-sha256"] = body_sha
    h["x-amz-date"] = amz_date
    h["x-amz-target"] = awsjson_target(p, op)
    return h

# Build the unsigned aws.core Request for an awsJson operation: POST "/" to
# `host`, the shared header set, no query, `body` as the payload. `body` is the
# operation input already serialized to JSON (typically `input.to_json()`).
def awsjson_build_request(
    AwsJson p,
    str region,
    str host,
    str op,
    str body,
    str amz_date,
) -> Request:
    auto body_sha = payload_hash(body)
    auto headers = awsjson_headers(p, host, body_sha, amz_date, op)
    dict[str, str] query = {}
    return Request(
        method="POST",
        service=p.service,
        region=region,
        host=host,
        path="/",
        query=query,
        headers=headers,
        body=body,
    )

# Serialize + SigV4-sign an awsJson operation at the given timestamps and return
# ready-to-send HTTP/1.1 request text. `host` is the resolved service endpoint;
# `body` is the serialized input shape. This is the request half of the codec.
def awsjson_request(
    AwsJson p,
    Credentials creds,
    str region,
    str host,
    str op,
    str body,
    str amz_date,
    str date_stamp,
) -> str:
    auto req = awsjson_build_request(p, region, host, op, body, amz_date)
    return sign_request(creds, req, amz_date, date_stamp)

# Serialize + sign an awsJson operation using the current UTC time and the
# service's regional endpoint — the usual live path (mirrors aws.core's
# `sign_request_now`). `region` resolves the host; the SigV4 timestamp is stamped
# from datetime.now().
def awsjson_request_now(
    AwsJson p,
    Credentials creds,
    str region,
    str op,
    str body,
) -> str:
    auto host = regional_host(p.service, region)
    auto t = signing_time_now()
    return awsjson_request(p, creds, region, host, op, body, t.amz_date, t.date_stamp)

# ---------------------------------------------------------------------------
# Error dispatch (the `__type` / X-Amzn-ErrorType shape name)
# ---------------------------------------------------------------------------

# Index of the last occurrence of `sep` in `s`, or -1 if absent (there is no
# str.rfind yet). Used to strip an awsJson error type's dotted/`#` namespace.
def awsjson_last_index(str s, str sep) -> int64:
    auto idx = -1
    auto start = 0
    while start <= len(s):
        auto rest = s[start:len(s)]
        auto k = rest.find(sep)
        if k < 0:
            break
        idx = start + k
        start = idx + len(sep)
    return idx

# Strip an awsJson error type down to the bare shape name. AWS sends the name in
# several shapes:
#   "ResourceNotFoundException"                         (already bare)
#   "com.amazonaws.dynamodb.v20120810#ResourceNotFoundException"  (namespace#Name)
#   "ResourceNotFoundException:http://internal..."      (Name:url, header form)
# Drop a trailing ":url" first, then keep only the text after the last "#"
# (botocore's `rsplit('#', 1)[-1]` after `split(':', 1)[0]`).
def awsjson_strip_error_code(str raw) -> str:
    auto code = raw
    auto c = code.find(":")
    if c >= 0:
        code = code[0:c]
    auto h = awsjson_last_index(code, "#")
    if h >= 0:
        code = code[h + 1:len(code)]
    return code

# The awsJson error shape name for a response: prefer the body's `__type` field,
# then the `x-amzn-errortype` response header, stripped to the bare shape name.
# Returns "" when neither is present.
def awsjson_error_code(Response resp) -> str:
    auto raw = ""
    Optional[str] jtype = json_string_field(resp.body, "__type")
    raw = jtype.unwrap_or(raw)
    if len(raw) == 0:
        Optional[str] htype = resp.headers.get("x-amzn-errortype")
        raw = htype.unwrap_or(raw)
    if len(raw) == 0:
        return ""
    return awsjson_strip_error_code(raw)

# The error message an awsJson fault carries: services use either "message" or
# "Message" in the body (both occur across services).
def awsjson_error_message(Response resp) -> str:
    auto message = ""
    Optional[str] lower = json_string_field(resp.body, "message")
    message = lower.unwrap_or(message)
    Optional[str] upper = json_string_field(resp.body, "Message")
    message = upper.unwrap_or(message)
    return message

# Dispatch an awsJson response to an error. Returns none on a 2xx status; on a
# fault, an aws.core.AwsError with the stripped `__type`/header shape name, the
# message, and the HTTP status — the typed-ish error the SDK surfaces today.
def awsjson_error(Response resp) -> Optional[AwsError]:
    if is_success(resp.status):
        return Optional.None
    return Optional.Some(
        AwsError(
            code=awsjson_error_code(resp),
            message=awsjson_error_message(resp),
            status=resp.status,
        ),
    )
