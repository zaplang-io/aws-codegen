# aws.errors — typed service errors on top of aws.core's error dispatch (#361).
#
# `core.parse_error` already extracts a flat `AwsError { code, message, status }`
# from any non-2xx `Response` (awsJson `__type`/`code`, rest-xml `<Code>`, plus a
# body `message`/`Message`). That is the string-matching baseline: a caller tells
# NoSuchKey from NoSuchBucket by comparing `err.code` to a literal. This module is
# the typed layer that lets a caller branch on the *kind* of error instead —
# `match s3_error_kind(err.code): case S3ErrorKind.NoSuchKey:` — reusing the same
# open-enum shape the protocol codecs already use (a named variant per modeled
# case + an `Unknown` catch-all).
#
# WHAT THE LANGUAGE SUPPORTS TODAY (the shape of this module follows from it).
# Zap's enums with payload variants + exhaustive `match` are fully shipped
# (zaplang-io/zap#51), so the typed *dispatch* is an enum + `match`. Zap's
# exception machinery (`raise`/`try`/`except`/`finally`, #22, with faults made
# catchable by #383/#401) today only `raise`s a **str** message and matches
# `except` **catch-all** (the clause's type is parsed but ignored; `as e` binds
# the message string) — type-directed `except NoSuchKey:` dispatch and raising a
# typed payload are deferred in the compiler. So the exception bridge here raises
# a formatted message a single `except ... as e:` recovers; fine-grained "which
# error" branching is the enum `match`, not multiple `except` clauses. When the
# compiler gains type-directed `except`, the SAME per-service enum becomes the
# exception type set with no change to the generated classifier (see DECISIONS.md
# D-0006 and the generator contract).
#
# Additive: `core.parse_error` and the `core.AwsError` shape are untouched. This
# module imports them and complements them (richer carrier + rest-json header
# fallback + code normalization); nothing in the signing/codec/oracle path depends
# on it.

import core

# ---------------------------------------------------------------------------
# The base service-error carrier
# ---------------------------------------------------------------------------

# A surfaced AWS service error with the fields a caller actually inspects: the
# (normalized) error `code`, the human `message`, the `request_id` for support
# correlation, and the `http_status`. This is `core.AwsError` plus the request id
# — the base shape every per-service error maps from. It is a plain value (the
# unwinder cannot yet carry a struct, so this is inspected, not thrown; the
# exception bridge below raises its formatted message).
struct AwsServiceError:
    str code
    str message
    str request_id
    int64 http_status

# ---------------------------------------------------------------------------
# Error-code normalization (awsJson `__type`, rest-json header shapes)
# ---------------------------------------------------------------------------

# Index of the last occurrence of `sep` in `s`, or -1 (there is no str.rfind).
# Mirrors `awsjson.awsjson_last_index`, kept local so this typed layer depends
# only on `core`.
def last_index(str s, str sep) -> int64:
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

# Normalize a raw AWS error code to the bare shape name used for matching. AWS
# spells the code three ways across protocols:
#   * a bare name                         "NoSuchKey"
#   * a fully-qualified shape id          "com.amazonaws.dynamodb#NoSuchKey"
#   * a name with a trailing URL/suffix   "NoSuchKey:" / "NoSuchKey:http://..."
# Botocore keys its error map on the bare name (`split(':', 1)[0]` then
# `rsplit('#', 1)[-1]`), so we drop everything from the first ':' and then keep
# only the text after the last '#'. An already-bare code passes through
# unchanged. Mirrors `awsjson.awsjson_strip_error_code`.
def error_code(str raw) -> str:
    auto name = raw
    auto colon = name.find(":")
    if colon >= 0:
        name = name[0:colon]
    auto hash = last_index(name, "#")
    if hash >= 0:
        name = name[hash + 1:len(name)]
    return name

# ---------------------------------------------------------------------------
# Building the carrier from a Response
# ---------------------------------------------------------------------------

# The AWS request id from a response's (lowercased) header map: rest/xml services
# send `x-amz-request-id`, awsJson/rest-json services `x-amzn-requestid`. Empty
# when neither is present.
def request_id_of(core.Response resp) -> str:
    Optional[str] a = resp.headers.get("x-amzn-requestid")
    if a.is_some():
        return a.unwrap()
    Optional[str] b = resp.headers.get("x-amz-request-id")
    return b.unwrap_or("")

# Promote a flat `core.AwsError` + its `Response` to the richer carrier: the code
# is normalized (`error_code`) and the request id read from the headers.
def service_error(core.AwsError e, core.Response resp) -> AwsServiceError:
    return AwsServiceError(
        code=error_code(e.code),
        message=e.message,
        request_id=request_id_of(resp),
        http_status=e.status,
    )

# Parse a typed service error out of a response, or none on a 2xx. Wraps
# `core.parse_error` and, when the body carried no code (the rest-json case,
# where the error shape is in the `x-amzn-errortype` header rather than the
# body), falls back to that header. The returned code is normalized.
def service_error_from_response(core.Response resp) -> Optional[AwsServiceError]:
    Optional[core.AwsError] base = core.parse_error(resp)
    if base.is_none():
        return Optional.None
    auto e = base.unwrap()
    if len(e.code) == 0:
        Optional[str] hdr = resp.headers.get("x-amzn-errortype")
        if hdr.is_some():
            return Optional.Some(
                AwsServiceError(
                    code=error_code(hdr.unwrap()),
                    message=e.message,
                    request_id=request_id_of(resp),
                    http_status=e.status,
                ),
            )
    return Optional.Some(service_error(e, resp))

# ---------------------------------------------------------------------------
# The exception bridge (raise / catch)
# ---------------------------------------------------------------------------

# A one-line human form of a service error:
#   "<code>: <message> (request-id=<id>, http-status=<n>)"
# The request-id clause is omitted when there is no id. This is the string the
# raise bridge throws, so a `try: ... except ... as e:` handler gets a readable,
# code-leading message.
def format_error(AwsServiceError e) -> str:
    auto status = "http-status=" + str(e.http_status)
    if len(e.request_id) > 0:
        status = "request-id=" + e.request_id + ", " + status
    return e.code + ": " + e.message + " (" + status + ")"

# Raise a service error as an exception. Because `except` matching is catch-all
# today, a single `except ... as e:` clause recovers the formatted message; branch
# on the specific error with the per-service enum `match` (below) instead of
# multiple `except` clauses.
def raise_error(AwsServiceError e):
    raise format_error(e)

# Raise if `resp` carries a service error; return normally on success. Lets a
# caller write the fail-fast ergonomic:
#   try:
#       errors.check_response(resp)
#   except Exception as e:
#       ...  # e is the formatted message
def check_response(core.Response resp):
    Optional[AwsServiceError] e = service_error_from_response(resp)
    if e.is_some():
        raise_error(e.unwrap())

# ---------------------------------------------------------------------------
# The per-service typed-error enum pattern (CONTRACT — implemented per service)
# ---------------------------------------------------------------------------
#
# aws-core owns the base carrier + bridge above; each SERVICE owns its typed-error
# enum and classifier, which aws-codegen emits from the service model (the #361
# follow-up, gated on #364 — see DECISIONS.md D-0006). The shape every service
# follows, proven here against the hand-wired S3 oracle in `s3.zap`:
#
#   enum <Service>ErrorKind:
#       <ModeledError1>            # one bare variant per modeled error shape
#       <ModeledError2>
#       ...
#       Unknown(str code)          # open-enum catch-all: carries the raw code
#
#   def <service>_error_kind(str code) -> <Service>ErrorKind:
#       auto name = errors.error_code(code)    # normalize first
#       if name == "<ModeledError1>":
#           return <Service>ErrorKind.<ModeledError1>
#       ...
#       return <Service>ErrorKind.Unknown(name)
#
#   def <service>_error_name(<Service>ErrorKind k) -> str:
#       match k:                               # exhaustive; module-local `match`
#           case <Service>ErrorKind.<ModeledError1>:
#               return "<ModeledError1>"
#           ...
#           case <Service>ErrorKind.Unknown(c):
#               return "Unknown(" + c + ")"
#
# A caller classifies a response and dispatches through the typed value:
#
#   Optional[errors.AwsServiceError] e = errors.service_error_from_response(resp)
#   if e.is_some():
#       auto kind = s3.s3_error_kind(e.unwrap().code)
#       ...  # branch on `kind` via the service's dispatcher, e.g. s3.s3_error_name
#
# The `match` on `<Service>ErrorKind` lives IN the service module (the generated
# `*_error_name` / dispatch helpers), because enum variant patterns resolve on a
# two-segment `Enum.Variant` path — a caller's own `match` with a module-qualified
# `s3.S3ErrorKind.NoSuchKey` pattern is not resolved by the compiler yet (lowering
# keys the variant on the first path segment). That — and type-directed
# `except NoSuchKey:` dispatch, also deferred — are the two compiler features that
# will let a caller branch inline; the enum defined here is exactly their
# substrate (DECISIONS.md D-0006 records both as the generator-contract gate).
#
# The `Unknown(code)` arm guarantees forward compatibility: a service that adds a
# new error shape does not break a caller built against an older model — the new
# code lands in `Unknown` until the client is regenerated.
