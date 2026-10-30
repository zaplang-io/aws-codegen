# aws.restxml — the rest-xml protocol codec.
#
# rest-xml is AWS's REST protocol with an XML document body: S3, Route53,
# CloudFront and others speak it. Like rest-json (#345) it is the
# protocol-agnostic HTTP binding layer (aws.binding) with a document serializer
# bolted on — only the body format differs (XML instead of JSON), so this module
# reuses aws.binding verbatim for URI labels, query, headers, prefix-headers and
# the httpPayload-vs-document split, and swaps in an XML serializer for the
# document body:
#   * request  — build an `HttpBinding` (URI labels, query, headers,
#     prefix-headers), attach an XML document body (the operation's document
#     members, serialized from an `xml.XmlElement` tree) or a raw httpPayload
#     member, assemble a core `Request`, and SigV4-sign it via `binding_sign`;
#   * response — status + headers map to output members via the binding helpers
#     (`bound_status` / `bound_header` / `collect_prefix_headers`), and the XML
#     body is parsed with the `xml` module and read back with the
#     `rest_xml_*_values` helpers (inverse of the serialize helpers);
#   * errors   — the rest-xml error shape, either the bare `<Error>` document S3
#     emits or the `<ErrorResponse><Error>…</Error></ErrorResponse>` wrapper the
#     other rest-xml services use, surfaced as an aws.core.AwsError (code +
#     message + status), matching how awsjson/restjson surface errors.
#
# The XML tree is built and parsed with the core `xml` module (zaplang-io/zap#351
# — `import xml`), which owns parse/serialize and is byte-deterministic; this
# codec owns only the AWS *shape-trait → XML primitive* mapping (xmlName /
# locationName, xmlNamespace + prefix, xmlAttribute, xmlFlattened lists, wrapped
# lists, member naming). Nothing here hand-rolls XML lexing or escaping.
#
# Because the serialize helpers below produce the canonical request bytes, this
# module is the ORACLE the aws-codegen XML emitter (#354) byte-diffs its
# generated output against — so the helpers map one trait combination to exactly
# one deterministic XML shape.
#
# Depends on aws.core + aws.binding (bundled ahead of this file; see FRICTION.md
# #1 on why there is no `import aws.core` yet). Note aws.core already carries a
# best-effort string-scanning `xml_element_text` / `parse_error` for the baseline
# path; this module is the full xml-module-backed codec and uses distinct
# `rest_xml_*` names so the two coexist in the concatenated bundle.

import binding
import core
import xml
import base64
import datetime

# ---------------------------------------------------------------------------
# Content type
# ---------------------------------------------------------------------------

# The rest-xml document media type. Sent as Content-Type for an XML document
# body (not for a raw httpPayload member, which carries its own media type).
def rest_xml_content_type() -> str:
    return "application/xml"

# ---------------------------------------------------------------------------
# Request: attach the body to a binding
# ---------------------------------------------------------------------------

# Attach a serialized XML document as the request body and set
# Content-Type: application/xml. `document` is the XML the caller produced with
# `rest_xml_serialize` over the operation's document members (the empty string
# when the operation has no XML body). This is the only place rest-xml commits to
# XML — the binding layer stays format-agnostic.
def rest_xml_document(binding.HttpBinding b, str document) -> binding.HttpBinding:
    return binding.with_payload(
        b,
        binding.PayloadKind.Document,
        document,
        rest_xml_content_type(),
    )

# Bind one member as the raw request body (httpPayload), carried verbatim with
# its own media type (e.g. "application/octet-stream" for a blob, or an XML
# structure member serialized on its own). No framing — the member's bytes ARE
# the body. Mirrors aws.restjson.rest_json_raw_payload.
def rest_xml_raw_payload(
    binding.HttpBinding b,
    str raw,
    str content_type,
) -> binding.HttpBinding:
    return binding.with_payload(b, binding.PayloadKind.Raw, raw, content_type)

# ---------------------------------------------------------------------------
# Request: build + sign
# ---------------------------------------------------------------------------

# Assemble and SigV4-sign a rest-xml request from a binding at explicit signing
# timestamps, returning ready-to-send HTTP/1.1 text. Resolves the URI labels and
# query, assembles the headers (including the XML Content-Type), and signs via
# `binding_sign` (the binding path contract — the path is already wire-encoded).
# The core signer's canonicalization is unchanged, so the pinned SigV4 vectors
# are unaffected.
def rest_xml_sign(
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

# Build + sign a rest-xml request using the current UTC time (the live path).
def rest_xml_request(
    core.Credentials creds,
    binding.HttpBinding b,
    str service,
    str region,
    str host,
) -> str:
    auto t = core.signing_time_now()
    return rest_xml_sign(creds, b, service, region, host, t.amz_date, t.date_stamp)

# ---------------------------------------------------------------------------
# XML body serialization: AWS shape traits → xml primitives (the oracle)
# ---------------------------------------------------------------------------
#
# Each helper maps one Smithy trait combination to exactly one deterministic XML
# shape. `xml.dumps` emits attrs + children in insertion order with no sort, so
# the canonical bytes are fixed by the order in which these are called. Element
# names are the model's `xmlName`/`locationName` (or the member name otherwise) —
# the caller passes the resolved name, this layer never guesses it.

# A document root element `<name>` with no namespace declaration.
def rest_xml_root(str name) -> XmlElement:
    return xml.element(name)

# A document root carrying a default-namespace declaration (the xmlNamespace
# trait without a prefix): `<name xmlns="uri">`. The namespace propagates to
# descendants, so nested elements need no further declaration.
def rest_xml_root_ns(str name, str namespace) -> XmlElement:
    auto e = xml.element(name)
    e.set_attr("xmlns", namespace)
    return e

# A document root carrying a prefixed-namespace declaration (the xmlNamespace
# trait with a prefix): `<prefix:name xmlns:prefix="uri">`. The element tag is
# written with the prefix; `local_name()` strips it back to `name` on parse.
def rest_xml_root_prefixed(str name, str prefix, str namespace) -> XmlElement:
    auto e = xml.element(prefix + ":" + name)
    e.set_attr("xmlns:" + prefix, namespace)
    return e

# Set a member carried as an XML attribute (the xmlAttribute trait):
# `<e name="value">`. Returns `e` so attribute sets chain.
def rest_xml_attribute(XmlElement e, str name, str value) -> XmlElement:
    e.set_attr(name, value)
    return e

# Append a scalar member `<name>value</name>` to `parent`. `value` is the
# member already encoded to its XML text form (see the scalar encodings below for
# timestamp/blob). Returns `parent` so sibling members chain.
def rest_xml_scalar(XmlElement parent, str name, str value) -> XmlElement:
    auto child = xml.element(name)
    child.set_text(value)
    parent.add_child(child)
    return parent

# Open a nested-structure member `<name>…</name>` under `parent` and return the
# NEW child element so the caller can populate its members. `XmlElement` is a
# reference, so mutating the returned child after this call is reflected in the
# tree. Use `rest_xml_scalar` / further `rest_xml_struct` on the returned element.
def rest_xml_struct(XmlElement parent, str name) -> XmlElement:
    auto child = xml.element(name)
    parent.add_child(child)
    return child

# Append a pre-built child element to `parent` (for a member assembled
# elsewhere). Returns `parent` so siblings chain.
def rest_xml_child(XmlElement parent, XmlElement child) -> XmlElement:
    parent.add_child(child)
    return parent

# A flattened list (the xmlFlattened trait): the members are repeated siblings
# under `parent` with NO wrapper element — `<member>v0</member><member>v1</member>`.
# Returns `parent`.
def rest_xml_flat_list(XmlElement parent, str member, list[str] values) -> XmlElement:
    for v in values:
        auto e = xml.element(member)
        e.set_text(v)
        parent.add_child(e)
    return parent

# A wrapped list (the default list encoding): the members sit inside a wrapper
# element — `<wrapper><member>v0</member><member>v1</member></wrapper>`. The
# wrapper tag is the list member's `xmlName` (often the member name); the member
# tag defaults to "member" when the model gives none. Returns `parent`.
def rest_xml_wrapped_list(
    XmlElement parent,
    str wrapper,
    str member,
    list[str] values,
) -> XmlElement:
    auto w = xml.element(wrapper)
    for v in values:
        auto e = xml.element(member)
        e.set_text(v)
        w.add_child(e)
    parent.add_child(w)
    return parent

# Serialize a built document tree to its canonical rest-xml bytes. Thin wrapper
# over `xml.dumps` (deterministic: list order, self-closing empty elements).
def rest_xml_serialize(XmlElement root) -> str:
    return xml.dumps(root)

# ---------------------------------------------------------------------------
# AWS scalar XML text encodings
# ---------------------------------------------------------------------------
#
# rest-xml carries scalars as element text (xml.dumps escapes & < > for us). A
# few member types have an AWS-specific text form; these produce it, to pass as
# the `value` of `rest_xml_scalar`. Unlike the JSON encodings they carry NO
# surrounding quotes — XML text is not quoted.

# A timestamp as ISO-8601 date-time text — the rest-xml default timestamp
# encoding, e.g. "2015-08-30T12:36:00Z".
def xml_timestamp_iso8601(DateTime dt) -> str:
    return datetime.strftime(dt, "%Y-%m-%dT%H:%M:%SZ")

# A timestamp as Unix epoch SECONDS text (the `@timestampFormat("epoch-seconds")`
# form some rest-xml members use).
def xml_timestamp_epoch(DateTime dt) -> str:
    return str(datetime.to_timestamp(dt))

# A blob member as base64 text (standard alphabet, padded). Round-trips with
# `base64.decode`.
def xml_blob(bytes b) -> str:
    return base64.encode(b)

# ---------------------------------------------------------------------------
# Response: body + XML parse + member reads (inverse of the serialize helpers)
# ---------------------------------------------------------------------------

# The raw XML document body of a response.
def rest_xml_body(core.Response resp) -> str:
    return resp.body

# Parse a response body into the XML DOM root. Caller navigates with the `xml`
# module methods (`find` / `find_all` / `get_attr` / `get_text`) or the
# `rest_xml_*_values` helpers below.
def rest_xml_parse(core.Response resp) -> XmlElement:
    return xml.parse(resp.body)

# Read a flattened list back: every direct child of `parent` named `member`, in
# document order (inverse of `rest_xml_flat_list`).
def rest_xml_flat_list_values(XmlElement parent, str member) -> list[str]:
    list[str] out = []
    for e in parent.find_all(member):
        out.append(e.get_text())
    return out

# Read a wrapped list back: the `member` children inside the `wrapper` element,
# in document order (inverse of `rest_xml_wrapped_list`). Empty when the wrapper
# is absent.
def rest_xml_wrapped_list_values(
    XmlElement parent,
    str wrapper,
    str member,
) -> list[str]:
    list[str] out = []
    Optional[XmlElement] w = parent.find(wrapper)
    if w.is_none():
        return out
    for e in w.unwrap().find_all(member):
        out.append(e.get_text())
    return out

# ---------------------------------------------------------------------------
# Error dispatch (the rest-xml <Error> / <ErrorResponse> shapes)
# ---------------------------------------------------------------------------

# The `<Error>` element of a parsed rest-xml error document, handling both wire
# shapes: the bare S3 form where the root IS `<Error>`, and the
# `<ErrorResponse><Error>…</Error></ErrorResponse>` wrapper the other rest-xml
# services use. None when neither is present.
def rest_xml_error_element(XmlElement root) -> Optional[XmlElement]:
    if root.local_name() == "Error":
        return Optional.Some(root)
    return root.find("Error")

# The text of a named field inside the `<Error>` element, or "" when the document
# is not a recognizable rest-xml error (empty/non-XML body, no `<Error>`, or the
# field is absent). Used for both `<Code>` and `<Message>`.
def rest_xml_error_field(core.Response resp, str field) -> str:
    if len(resp.body) == 0:
        return ""
    if not resp.body.startswith("<"):
        return ""
    auto root = rest_xml_parse(resp)
    Optional[XmlElement] err_opt = rest_xml_error_element(root)
    if err_opt.is_none():
        return ""
    Optional[XmlElement] f = err_opt.unwrap().find(field)
    if f.is_none():
        return ""
    return f.unwrap().get_text()

# The rest-xml error code for a response (the `<Error><Code>` text), or "".
def rest_xml_error_code(core.Response resp) -> str:
    return rest_xml_error_field(resp, "Code")

# The rest-xml error message for a response (the `<Error><Message>` text), or "".
def rest_xml_error_message(core.Response resp) -> str:
    return rest_xml_error_field(resp, "Message")

# Dispatch a response to an AwsError, or none on a 2xx status. The code and
# message come from the `<Error>` element; the status is the HTTP status. The
# per-service modeled-exception registry (member fields, retryable flags) is
# future work — this is the shape error dispatch produces now, and it matches
# core's `AwsError` so retry/classification code is shared across protocols.
def rest_xml_error(core.Response resp) -> Optional[core.AwsError]:
    if core.is_success(resp.status):
        return Optional.None
    return Optional.Some(
        core.AwsError(
            code=rest_xml_error_code(resp),
            message=rest_xml_error_message(resp),
            status=resp.status,
        ),
    )
