# aws.query — the AWS `query` protocol codec and its `ec2` variant.
#
# The query protocol is AWS's oldest wire format: IAM, STS, SNS, SQS (legacy),
# CloudWatch (query), ELB and others speak it. Unlike the REST protocols
# (#345/#352) nothing is bound to the URI, the query string, or individual
# headers — every operation is a POST to "/" whose entire input is a flat
# `application/x-www-form-urlencoded` body, with the operation selected by an
# `Action` parameter and the model version pinned by a `Version` parameter. The
# RESPONSE is XML (parsed with the core `xml` module, #351), wrapped in an
# `<OperationNameResponse>` envelope; errors are the `<ErrorResponse><Error>`
# document. This module is the protocol-agnostic half: it rides on aws.core's
# Request/Response model and SigV4 signer (bundled ahead of this file — see
# FRICTION.md #1 on why there is no `import aws.core`), exactly like aws.awsjson.
#
# The `ec2` protocol (EC2 only) is the same wire format with three deltas, all
# applied by the CALLER through the resolved names it passes here (this layer
# never guesses a member name — like aws.restxml it maps a trait combination to
# one deterministic shape, and the caller supplies the name):
#   * member keys are Capitalized (the `ec2QueryName` trait, else the capitalized
#     `xmlName`, else the capitalized member name) — the caller passes the
#     resolved key, so `query_scalar`/`query_flat_list` serve ec2 unchanged;
#   * lists are ALWAYS flattened — `Name.N`, never `Name.member.N` — so ec2 uses
#     `query_flat_list` where awsQuery wrapped lists use `query_list`;
#   * the XML response has NO `<…Result>` wrapper (result members are direct
#     children of the `<…Response>` root) and errors are `<Response><Errors>
#     <Error>…`, so ec2 parses with `ec2_result` / `ec2_error` below.
#
# REQUEST serialization is the ORACLE the aws-codegen query/ec2 emitter (#354)
# byte-diffs its generated bodies against, so the form-encoding and the list/map
# key conventions here map one trait combination to exactly one deterministic
# byte sequence. Parameters are emitted in insertion order (Action, Version, then
# members in model order) with no sort — botocore's wire order — and the SigV4
# signature covers the body verbatim, so the order IS part of the contract.
#
# Depends on aws.core (bundled ahead of this file).

import core
import endpoints
import xml
import base64
import datetime
import url

# ---------------------------------------------------------------------------
# The parameter accumulator
# ---------------------------------------------------------------------------

# One serialized form parameter: a fully-resolved key and its raw (un-encoded)
# value. `query_encode` percent-encodes both at the end. Keys are built by the
# serialize helpers using the AWS query dotted-path conventions; values are the
# member already rendered to its scalar text form (see the scalar encodings).
struct QueryPair:
    str key
    str value

# Start a parameter list for an operation: `Action` then `Version`, always first
# and in that order (the botocore wire order). Members are appended after, in
# model order, by the serialize helpers.
def query_params(str action, str version) -> list[QueryPair]:
    list[QueryPair] p = []
    p.append(QueryPair(key="Action", value=action))
    p.append(QueryPair(key="Version", value=version))
    return p

# The query document media type, matching the official SDKs (botocore sends the
# charset). Signed as the content-type header, so it is part of the request bytes.
def query_content_type() -> str:
    return "application/x-www-form-urlencoded; charset=utf-8"

# ---------------------------------------------------------------------------
# Request serialization: AWS query key conventions → form parameters (the oracle)
# ---------------------------------------------------------------------------
#
# Each helper appends to `p` and returns it, so calls chain and the caller is
# independent of whether a list is a value or a reference (it reassigns the
# result). Keys use "." as the path separator; "." is RFC-3986 unreserved, so
# `query_encode` leaves it literal — the dotted structure survives encoding.

# Join a member path segment onto a prefix: "prefix.name", or just "name" when
# there is no prefix (a top-level member). Used to build nested-structure keys —
# a struct member `Owner` with a field `Id` is key "Owner.Id".
def query_key(str prefix, str name) -> str:
    if len(prefix) == 0:
        return name
    return prefix + "." + name

# Append a scalar member `key=value`. `value` is the member already encoded to
# its query text form (see the scalar encodings below for timestamp/blob/bool).
# This also serves ec2 scalars — the caller passes the Capitalized key.
def query_scalar(list[QueryPair] p, str key, str value) -> list[QueryPair]:
    p.append(QueryPair(key=key, value=value))
    return p

# A wrapped list (the default awsQuery list encoding): each item is
# `name.member.INDEX`, 1-based. `member` is "member" unless the list member's
# `xmlName` overrides it — the caller passes the resolved segment.
def query_list(
    list[QueryPair] p,
    str name,
    str member,
    list[str] values,
) -> list[QueryPair]:
    auto i = 1
    for v in values:
        auto key = name + "." + member + "." + str(i)
        p.append(QueryPair(key=key, value=v))
        i = i + 1
    return p

# A flattened list: each item is `name.INDEX`, 1-based, with no `member` segment.
# This is the awsQuery `@xmlFlattened` encoding AND every ec2 list (ec2 always
# flattens), so the `ec2` variant uses this for lists.
def query_flat_list(list[QueryPair] p, str name, list[str] values) -> list[QueryPair]:
    auto i = 1
    for v in values:
        p.append(QueryPair(key=name + "." + str(i), value=v))
        i = i + 1
    return p

# A wrapped map (the default awsQuery map encoding): each entry is
# `name.entry.INDEX.key` / `name.entry.INDEX.value`, 1-based, paired by position
# across `keys` and `values` (same length). `key_name`/`value_name` are "key"/
# "value" unless the model's `xmlName` overrides them (caller-resolved).
def query_map(
    list[QueryPair] p,
    str name,
    str key_name,
    str value_name,
    list[str] keys,
    list[str] values,
) -> list[QueryPair]:
    auto i = 0
    auto n = len(keys)
    while i < n:
        auto prefix = name + ".entry." + str(i + 1)
        p.append(QueryPair(key=prefix + "." + key_name, value=keys[i]))
        p.append(QueryPair(key=prefix + "." + value_name, value=values[i]))
        i = i + 1
    return p

# A flattened map (the awsQuery `@xmlFlattened` map encoding): each entry is
# `name.INDEX.key` / `name.INDEX.value`, 1-based, with no `entry` segment.
def query_flat_map(
    list[QueryPair] p,
    str name,
    str key_name,
    str value_name,
    list[str] keys,
    list[str] values,
) -> list[QueryPair]:
    auto i = 0
    auto n = len(keys)
    while i < n:
        auto prefix = name + "." + str(i + 1)
        p.append(QueryPair(key=prefix + "." + key_name, value=keys[i]))
        p.append(QueryPair(key=prefix + "." + value_name, value=values[i]))
        i = i + 1
    return p

# Serialize the parameter list to the canonical `x-www-form-urlencoded` body:
# `k=v` pairs joined by "&", each key and value RFC-3986 percent-encoded
# (`url.quote`, space → %20, unreserved `-._~` kept). Insertion order, no sort,
# so the bytes are fixed by the order the helpers were called. These bytes are
# the request payload the SigV4 signer hashes, and the oracle for #354.
def query_encode(list[QueryPair] p) -> str:
    auto out = ""
    auto first = True
    for pair in p:
        auto chunk = url.quote(pair.key) + "=" + url.quote(pair.value)
        if first:
            out = chunk
            first = False
        else:
            out = out + "&" + chunk
    return out

# ---------------------------------------------------------------------------
# AWS scalar query text encodings
# ---------------------------------------------------------------------------
#
# query carries scalars as the raw (pre-encoding) value of a form parameter.
# A few member types have an AWS-specific text form; these produce it, to pass
# as the `value` of `query_scalar` (or an item of a list/map). `query_encode`
# percent-encodes the result, so these return the plain text, not encoded bytes.

# A boolean member as the lowercase literal "true"/"false" (the query encoding).
def query_bool(bool b) -> str:
    if b:
        return "true"
    return "false"

# A timestamp as ISO-8601 date-time text — the query default timestamp encoding,
# e.g. "2015-08-30T12:36:00Z".
def query_timestamp_iso8601(DateTime dt) -> str:
    return datetime.strftime(dt, "%Y-%m-%dT%H:%M:%SZ")

# A timestamp as Unix epoch SECONDS text (the `@timestampFormat("epoch-seconds")`
# form).
def query_timestamp_epoch(DateTime dt) -> str:
    return str(datetime.to_timestamp(dt))

# A blob member as base64 text (standard alphabet, padded). Round-trips with
# `base64.decode`.
def query_blob(bytes b) -> str:
    return base64.encode(b)

# ---------------------------------------------------------------------------
# Request: build + sign
# ---------------------------------------------------------------------------

# Build the unsigned aws.core Request for a query/ec2 operation: POST "/" to
# `host`, Content-Type the form media type, the body the encoded parameters, no
# query string. Mirrors aws.awsjson.awsjson_build_request (another POST-"/"
# protocol) — the whole request is the shared headers plus the form body.
def query_build_request(
    str service,
    str region,
    str host,
    str body,
    str amz_date,
) -> core.Request:
    auto body_sha = core.payload_hash(body)
    dict[str, str] h = {}
    h["content-type"] = query_content_type()
    h["host"] = host
    h["x-amz-content-sha256"] = body_sha
    h["x-amz-date"] = amz_date
    dict[str, str] query = {}
    return core.Request(
        method="POST",
        service=service,
        region=region,
        host=host,
        path="/",
        query=query,
        headers=h,
        body=body,
    )

# Encode + SigV4-sign a query/ec2 operation at explicit signing timestamps and
# return ready-to-send HTTP/1.1 request text. `p` is the parameter list built
# with the serialize helpers. Signs via aws.core's `sign_request` (path "/", no
# query string), whose canonicalization is unchanged, so the pinned SigV4
# vectors are unaffected.
def query_sign(
    core.Credentials creds,
    str service,
    str region,
    str host,
    list[QueryPair] p,
    str amz_date,
    str date_stamp,
) -> str:
    auto body = query_encode(p)
    auto req = query_build_request(service, region, host, body, amz_date)
    return core.sign_request(creds, req, amz_date, date_stamp)

# Encode + sign a query/ec2 operation using the current UTC time and the
# service's regional endpoint — the usual live path (mirrors awsjson_request_now).
def query_request(
    core.Credentials creds,
    str service,
    str region,
    list[QueryPair] p,
) -> str:
    auto host = endpoints.regional_host(service, region)
    auto t = core.signing_time_now()
    return query_sign(creds, service, region, host, p, t.amz_date, t.date_stamp)

# ---------------------------------------------------------------------------
# Response: XML parse + envelope unwrap
# ---------------------------------------------------------------------------
#
# query/ec2 responses are XML. Parse with the core `xml` module (#351) and
# navigate with its methods (`find` / `find_all` / `get_text`). The envelope
# differs by variant, so two result-unwrap helpers:
#   * awsQuery  — `<FooResponse><FooResult>…</FooResult><ResponseMetadata>…`
#   * ec2Query  — `<FooResponse>…<requestId>…` (result members are direct
#     children of the response root; no Result wrapper).

# Parse a response body into the XML DOM root (the `<…Response>` element).
def query_parse(core.Response resp) -> XmlElement:
    return xml.parse(resp.body)

# The awsQuery result element: the `<…Result>` child of the response root (the
# caller passes the operation's result tag, e.g. "GetUserResult"). The result
# members are read from the returned element with the `xml` module methods.
def query_result(XmlElement root, str result_name) -> Optional[XmlElement]:
    return root.find(result_name)

# The ec2Query result element: the response root ITSELF — ec2 has no Result
# wrapper, so result members are direct children of `<…Response>`.
def ec2_result(XmlElement root) -> XmlElement:
    return root

# The `<RequestId>` of an awsQuery response (inside `<ResponseMetadata>`), or ""
# when absent.
def query_request_id(XmlElement root) -> str:
    Optional[XmlElement] meta = root.find("ResponseMetadata")
    if meta.is_none():
        return ""
    Optional[XmlElement] rid = meta.unwrap().find("RequestId")
    if rid.is_none():
        return ""
    return rid.unwrap().get_text()

# The `<requestId>` of an ec2Query response (a direct child of the root, lower-
# cased tag), or "" when absent.
def ec2_request_id(XmlElement root) -> str:
    Optional[XmlElement] rid = root.find("requestId")
    if rid.is_none():
        return ""
    return rid.unwrap().get_text()

# ---------------------------------------------------------------------------
# Error dispatch (the query `<ErrorResponse>` / ec2 `<Response><Errors>` shapes)
# ---------------------------------------------------------------------------

# The `<Error>` element of a parsed awsQuery error document
# (`<ErrorResponse><Error><Code>/<Message>…`), or none when the body is empty,
# non-XML, or carries no `<Error>`.
def query_error_element(core.Response resp) -> Optional[XmlElement]:
    if len(resp.body) == 0:
        return Optional.None
    if not resp.body.startswith("<"):
        return Optional.None
    auto root = query_parse(resp)
    return root.find("Error")

# The `<Error>` element of a parsed ec2Query error document
# (`<Response><Errors><Error><Code>/<Message>…`), or none when absent.
def ec2_error_element(core.Response resp) -> Optional[XmlElement]:
    if len(resp.body) == 0:
        return Optional.None
    if not resp.body.startswith("<"):
        return Optional.None
    auto root = query_parse(resp)
    Optional[XmlElement] errs = root.find("Errors")
    if errs.is_none():
        return Optional.None
    return errs.unwrap().find("Error")

# The text of a named field inside an `<Error>` element, or "" when the element
# or the field is absent. Used for both `<Code>` and `<Message>`.
def query_error_field(Optional[XmlElement] err, str field) -> str:
    if err.is_none():
        return ""
    Optional[XmlElement] f = err.unwrap().find(field)
    if f.is_none():
        return ""
    return f.unwrap().get_text()

# Dispatch an awsQuery response to an AwsError, or none on a 2xx status. The code
# and message come from `<ErrorResponse><Error>`; the status is the HTTP status.
# Matches aws.core's `AwsError` so retry/classification code is shared across
# protocols (like awsjson/restjson/restxml).
def query_error(core.Response resp) -> Optional[core.AwsError]:
    if core.is_success(resp.status):
        return Optional.None
    auto err = query_error_element(resp)
    return Optional.Some(
        core.AwsError(
            code=query_error_field(err, "Code"),
            message=query_error_field(err, "Message"),
            status=resp.status,
        ),
    )

# Dispatch an ec2Query response to an AwsError, or none on a 2xx status. The code
# and message come from `<Response><Errors><Error>`; the status is the HTTP
# status.
def ec2_error(core.Response resp) -> Optional[core.AwsError]:
    if core.is_success(resp.status):
        return Optional.None
    auto err = ec2_error_element(resp)
    return Optional.Some(
        core.AwsError(
            code=query_error_field(err, "Code"),
            message=query_error_field(err, "Message"),
            status=resp.status,
        ),
    )
