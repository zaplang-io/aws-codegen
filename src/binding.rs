//! rest-json HTTP binding classification.
//!
//! AWS's REST protocols place an operation's input members at HTTP *locations*
//! chosen by Smithy location traits — `httpLabel` (a `{Name}` / `{Name+}` URI
//! path segment), `httpQuery` (a query-string parameter), `httpHeader` (one
//! header), `httpPrefixHeaders` (a `string->string` header group), `httpPayload`
//! (one member carried as the raw body) — and everything left over is the
//! "document body", serialized as JSON for rest-json. This module is the pure
//! model analysis that partitions an operation's input into those locations and
//! decides whether the v0 generator can emit it; the Zap emission lives in
//! `emit.rs`, and the actual wire plumbing is the vendored `aws.binding` +
//! `aws.restjson`.
//!
//! The analysis is deliberately conservative, mirroring the awsJson path: a
//! member whose type the binding layer cannot render on the wire yet (a
//! collection query/header, a non-derivable document member, a non-derivable
//! structure payload) makes the whole operation *skipped* with a documented
//! reason, rather than emitting code that would not round-trip.

use crate::jsonbody::plan_enc;
use crate::model::{Model, Operation};
use crate::naming::escape_ident;
use crate::types::{resolve, ZapType};
use std::collections::HashMap;

/// A scalar member bound to a single wire slot (a path label, a query parameter,
/// or a header). `field` is the generated (escaped) field name on the input
/// struct, `wire` the on-the-wire name (the `locationName`), `ty` the resolved
/// type (so the emitter knows whether to `str(...)`-coerce a non-string), and
/// `optional` whether the member is `Optional[...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalarBind {
    pub field: String,
    pub wire: String,
    pub ty: ZapType,
    pub optional: bool,
    /// Greedy path label (`{Name+}`): only meaningful for URI labels, where it
    /// keeps "/" unescaped. Always false for query/header binds.
    pub greedy: bool,
    /// The raw (model) member name, so the emitter can recover the member's
    /// `ShapeRef` (for JSON document serialization, zaplang-io/zap#424).
    pub member: String,
    /// How the emitter turns the field into its wire string for this slot
    /// (zaplang-io/zap#425): a plain string, a stringified int, `"true"`/`"false"`
    /// for a bool, or a timestamp in the slot's format.
    pub fmt: BindFmt,
}

/// How a scalar bound to a path/query/header slot is rendered on the wire
/// (zaplang-io/zap#425). `Str` (a string or the plain wire string of an enum)
/// and `Int` (`str(..)`) are the #345 forms; `Bool` goes through the per-file
/// `_bind_bool` helper (`"true"`/`"false"`, never Zap's `str(bool)` = `"True"`),
/// and the timestamp forms use `datetime` with the AWS default per slot — ISO-8601
/// for a query parameter, RFC-822 (HTTP-date) for a header — or the member's
/// explicit `timestampFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindFmt {
    Str,
    Int,
    Bool,
    TsIso8601,
    TsRfc822,
    TsEpoch,
}

/// A list member bound to `httpQuery`: each element becomes a repeated query
/// parameter named `wire` (`?Tag=a&Tag=b`), carried by the binding's
/// `multi_query` map. v0 handles `list[str]` (and enum lists, carried as their
/// plain wire strings); other element types stay skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryListBind {
    pub field: String,
    pub wire: String,
    pub optional: bool,
}

/// How a raw `httpPayload` member becomes the request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadBody {
    /// A `blob` member: the body is `str(field)` (its UTF-8 bytes), content type
    /// `application/octet-stream`.
    Blob,
    /// A `string` member: the body is the field verbatim, content type
    /// `text/plain`.
    Str,
    /// A `structure` member serialized as the JSON body (content type
    /// `application/json`), carrying the raw (model) shape name. A derivable
    /// struct rides its `.to_json()`; a serializable-but-not-derivable one gets
    /// the explicit `#424` serializer, named off this shape (zaplang-io/zap#427).
    Document(String),
}

/// The single `httpPayload` member of a request, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadBind {
    pub field: String,
    pub body: PayloadBody,
    pub optional: bool,
}

/// The `httpPrefixHeaders` member: a `dict[str, str]` rendered as a header group
/// sharing `prefix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixHeadersBind {
    pub field: String,
    pub prefix: String,
    pub optional: bool,
}

/// The full binding plan for one rest-json operation: its HTTP method + URI
/// template and every input member sorted into its location. Produced by
/// [`plan_operation`]; consumed by the emitter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpBinding {
    pub method: String,
    pub path_template: String,
    /// The input shape name, when the operation has a (non-empty) input struct.
    pub input_shape: Option<String>,
    pub labels: Vec<ScalarBind>,
    pub query: Vec<ScalarBind>,
    /// List members bound to `httpQuery`, emitted as repeated query parameters
    /// (zaplang-io/zap#425).
    pub query_lists: Vec<QueryListBind>,
    pub headers: Vec<ScalarBind>,
    pub prefix_headers: Option<PrefixHeadersBind>,
    pub payload: Option<PayloadBind>,
    /// Unbound members forming the JSON document body (empty for a GET/DELETE
    /// with everything bound, or when a raw `payload` is present).
    pub document: Vec<ScalarBind>,
    /// Whether every document member is `@derive(Json)`-derivable. When true the
    /// body rides a `@derive(Json)` doc struct (`doc.to_json()`); when false the
    /// emitter serializes the members inline (zaplang-io/zap#424).
    pub document_all_derivable: bool,
}

impl OpBinding {
    /// Whether this operation sends a JSON document body (document members, no
    /// raw payload) — the emitter must then serialize those members.
    pub fn has_document_body(&self) -> bool {
        self.payload.is_none() && !self.document.is_empty()
    }
}

/// Where a scalar is bound, so [`scalar_bind_fmt`] can pick the right timestamp
/// default (ISO-8601 for a query parameter, RFC-822 HTTP-date for a header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Label,
    Query,
    Header,
}

/// Classify a scalar bound to a path/query/header slot into its wire rendering,
/// or `None` when the type is not a bindable scalar (a collection, a struct, a
/// blob, or a float — whose `str(...)` spelling does not match the AWS wire
/// form). Shared by the rest-json ([`plan_operation`]) and rest-xml
/// (`xml::plan_rest_xml`) binding layers so they stay in lock-step.
///
/// String/enum → [`BindFmt::Str`] (an enum is carried as its plain wire string),
/// integer → [`BindFmt::Int`], boolean → [`BindFmt::Bool`]; a timestamp uses its
/// explicit `timestampFormat` trait (member ref, else target shape) or the slot
/// default (query ISO-8601 / header RFC-822). URI labels accept only the #345
/// string/enum/int set — no AWS model binds a bool or timestamp to a label.
pub fn scalar_bind_fmt(
    model: &Model,
    r: &crate::model::ShapeRef,
    ty: &ZapType,
    slot: Slot,
) -> Option<BindFmt> {
    match ty {
        ZapType::Str | ZapType::Enum(_) => Some(BindFmt::Str),
        ZapType::Int => Some(BindFmt::Int),
        ZapType::Bool if slot != Slot::Label => Some(BindFmt::Bool),
        ZapType::DateTime if slot != Slot::Label => Some(timestamp_fmt(model, r, slot)),
        _ => None,
    }
}

/// The timestamp wire format for a bound member: its explicit `timestampFormat`
/// (on the member ref, else the target timestamp shape), else the AWS protocol
/// default for the slot — ISO-8601 for a query parameter, RFC-822 (HTTP-date)
/// for a header.
fn timestamp_fmt(model: &Model, r: &crate::model::ShapeRef, slot: Slot) -> BindFmt {
    let explicit = r.timestamp_format.as_deref().or_else(|| {
        model
            .shape(&r.shape)
            .and_then(|s| s.timestamp_format.as_deref())
    });
    match explicit {
        Some("iso8601") => BindFmt::TsIso8601,
        Some("rfc822") => BindFmt::TsRfc822,
        Some("unixTimestamp") => BindFmt::TsEpoch,
        _ if slot == Slot::Header => BindFmt::TsRfc822,
        _ => BindFmt::TsIso8601,
    }
}

/// The type the generated input field takes for a bound scalar slot: a string
/// enum is carried as its plain wire `str`, everything else keeps its type.
fn wire_type(ty: &ZapType) -> ZapType {
    match ty {
        ZapType::Enum(_) => ZapType::Str,
        other => other.clone(),
    }
}

/// Whether a list member bound to `httpQuery` can be emitted as repeated query
/// parameters: v0 supports a `list[str]`. A list of any other element type
/// (enum, struct, number, …) stays skipped, a documented #425 residual.
pub fn query_list_elem_ok(ty: &ZapType) -> bool {
    matches!(ty, ZapType::List(e) if **e == ZapType::Str)
}

/// Plan the rest-json binding for `op`, or return a short reason it must be
/// skipped (non-bindable scalar in the URI/query/header, non-derivable document
/// member, or an unsupported payload). `derivable` is the model-wide
/// derivability verdict (see `types::compute_derivable`).
pub fn plan_operation(
    model: &Model,
    op: &Operation,
    derivable: &HashMap<String, bool>,
    serializable: &HashMap<String, bool>,
) -> Result<OpBinding, String> {
    let http = op
        .http
        .as_ref()
        .ok_or("operation has no `http` trait (not a REST operation)")?;
    if http.method.is_empty() || http.request_uri.is_empty() {
        return Err("`http` trait is missing a method or requestUri".to_string());
    }

    let mut plan = OpBinding {
        method: http.method.clone(),
        path_template: http.request_uri.clone(),
        input_shape: None,
        labels: Vec::new(),
        query: Vec::new(),
        query_lists: Vec::new(),
        headers: Vec::new(),
        prefix_headers: None,
        payload: None,
        document: Vec::new(),
        document_all_derivable: true,
    };

    let input_ref = match op.input.as_ref() {
        Some(r) => r,
        // No input shape at all: a bare request over the fixed URI, no body.
        None => return Ok(plan),
    };
    let input = model
        .shape(&input_ref.shape)
        .filter(|s| s.is_structure())
        .ok_or("input is not a structure shape")?;
    if input.members.is_empty() {
        return Ok(plan);
    }
    plan.input_shape = Some(escape_ident(&input_ref.shape).0);

    let payload_member = input.payload.as_deref();

    for (mn, r) in &input.members {
        let field = escape_ident(mn).0;
        let wire = r.wire_name(mn).to_string();
        let ty = resolve(model, &r.shape);
        let optional = !input.required.contains(mn);

        // The raw httpPayload member (named by the shape's `payload` trait) is
        // always carried as the body, whatever its `location` (it has none).
        if payload_member == Some(mn.as_str()) {
            let body = match &ty {
                ZapType::Bytes => PayloadBody::Blob,
                ZapType::Str => PayloadBody::Str,
                // A structure payload becomes the JSON document body. A derivable
                // struct rides `.to_json()`; a serializable-but-not-derivable one
                // (nested/collection members) gets the explicit #424 serializer
                // (zaplang-io/zap#427). Key the verdict by the raw model shape
                // name — how `serializable`/`derivable` are keyed, which may
                // differ from the resolved (escaped) type name. Only a genuinely
                // non-serializable struct (free-form document / enum-keyed map)
                // stays skipped.
                ZapType::Struct(_) if *serializable.get(&r.shape).unwrap_or(&false) => {
                    PayloadBody::Document(r.shape.clone())
                }
                ZapType::Struct(_) => {
                    return Err(format!(
                        "httpPayload member `{mn}` is a non-serializable structure"
                    ))
                }
                other => {
                    return Err(format!(
                        "httpPayload member `{mn}` has unsupported type {}",
                        other.render()
                    ))
                }
            };
            plan.payload = Some(PayloadBind {
                field,
                body,
                optional,
            });
            continue;
        }

        match r.location.as_deref() {
            Some("uri") => {
                let fmt = scalar_bind_fmt(model, r, &ty, Slot::Label).ok_or_else(|| {
                    format!("httpLabel `{mn}` has unsupported type {}", ty.render())
                })?;
                let greedy = http.label_is_greedy(&wire);
                plan.labels.push(ScalarBind {
                    field,
                    wire,
                    greedy,
                    ty: wire_type(&ty),
                    optional,
                    member: mn.clone(),
                    fmt,
                });
            }
            Some("querystring") => {
                if let Some(fmt) = scalar_bind_fmt(model, r, &ty, Slot::Query) {
                    plan.query.push(ScalarBind {
                        field,
                        wire,
                        ty: wire_type(&ty),
                        optional,
                        greedy: false,
                        member: mn.clone(),
                        fmt,
                    });
                } else if query_list_elem_ok(&ty) {
                    plan.query_lists.push(QueryListBind {
                        field,
                        wire,
                        optional,
                    });
                } else {
                    return Err(format!(
                        "httpQuery `{mn}` has unsupported type {}",
                        ty.render()
                    ));
                }
            }
            Some("header") => {
                let fmt = scalar_bind_fmt(model, r, &ty, Slot::Header).ok_or_else(|| {
                    format!("httpHeader `{mn}` has unsupported type {}", ty.render())
                })?;
                plan.headers.push(ScalarBind {
                    field,
                    wire,
                    ty: wire_type(&ty),
                    optional,
                    greedy: false,
                    member: mn.clone(),
                    fmt,
                });
            }
            Some("headers") => {
                // httpPrefixHeaders: a dict[str, str] rendered as a header group.
                match &ty {
                    ZapType::Dict(k, v) if **k == ZapType::Str && **v == ZapType::Str => {
                        if plan.prefix_headers.is_some() {
                            return Err("multiple httpPrefixHeaders members".to_string());
                        }
                        plan.prefix_headers = Some(PrefixHeadersBind {
                            field,
                            prefix: wire,
                            optional,
                        });
                    }
                    _ => return Err(format!("httpPrefixHeaders `{mn}` is not a dict[str, str]")),
                }
            }
            Some("statusCode") => {
                // Response-only binding; ignore on the request side.
            }
            Some(other) => {
                return Err(format!("member `{mn}` has unknown location `{other}`"));
            }
            None => {
                // An unbound member: part of the JSON document body. A derivable
                // member rides `@derive(Json)`; a collection/nested member is
                // serialized inline by the explicit emitter (zaplang-io/zap#424);
                // anything else (a non-string-keyed map) is skipped.
                if plan_enc(model, r, derivable, serializable).is_none() {
                    return Err(format!(
                        "document member `{mn}: {}` is not serializable",
                        ty.render()
                    ));
                }
                if !member_derivable(&ty, derivable) {
                    plan.document_all_derivable = false;
                }
                plan.document.push(ScalarBind {
                    field,
                    wire,
                    ty,
                    optional,
                    greedy: false,
                    member: mn.clone(),
                    // Document members are serialized by the JSON emitter (plan_enc),
                    // not by a slot formatter, so `fmt` is unused here.
                    fmt: BindFmt::Str,
                });
            }
        }
    }

    Ok(plan)
}

/// Whether a document member's resolved type is `@derive(Json)`-serializable:
/// scalars/str/bytes/DateTime/open-enum always, a nested structure iff its
/// model-wide verdict says so, collections never (the #346 derive gap).
fn member_derivable(ty: &ZapType, derivable: &HashMap<String, bool>) -> bool {
    match ty {
        ZapType::List(_) | ZapType::Dict(..) => false,
        ZapType::Struct(n) => *derivable.get(n).unwrap_or(&false),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonbody::compute_json_serializable;
    use crate::types::compute_derivable;

    fn plan(model_json: &str, op: &str) -> Result<OpBinding, String> {
        let m = Model::from_json_str(model_json).unwrap();
        let d = compute_derivable(&m);
        let s = compute_json_serializable(&m, &d);
        plan_operation(&m, &m.operations[op], &d, &s)
    }

    // A model exercising every binding kind: a greedy + non-greedy label, a
    // renamed query param, a header, a raw blob payload; and a second op with
    // httpPrefixHeaders + a JSON document body (a string + an int member).
    const M: &str = r#"{
      "metadata":{"protocol":"rest-json","endpointPrefix":"svc","serviceId":"Svc"},
      "operations":{
        "PutObject":{"name":"PutObject",
          "http":{"method":"PUT","requestUri":"/b/{Bucket}/{Key+}"},
          "input":{"shape":"PutObjectRequest"}},
        "PutMeta":{"name":"PutMeta",
          "http":{"method":"POST","requestUri":"/meta"},
          "input":{"shape":"PutMetaRequest"}},
        "BadLabel":{"name":"BadLabel",
          "http":{"method":"GET","requestUri":"/t/{When}"},
          "input":{"shape":"BadLabelRequest"}},
        "BadDoc":{"name":"BadDoc",
          "http":{"method":"POST","requestUri":"/d"},
          "input":{"shape":"BadDocRequest"}},
        "NoHttp":{"name":"NoHttp","input":{"shape":"BadDocRequest"}},
        "PutDocReq":{"name":"PutDocReq",
          "http":{"method":"POST","requestUri":"/doc/{Id}"},
          "input":{"shape":"PutDocReqRequest"}},
        "PutDocOpt":{"name":"PutDocOpt",
          "http":{"method":"POST","requestUri":"/doc/{Id}"},
          "input":{"shape":"PutDocOptRequest"}}
      },
      "shapes":{
        "S":{"type":"string"},
        "I":{"type":"integer"},
        "T":{"type":"timestamp"},
        "Blob":{"type":"blob"},
        "StrMap":{"type":"map","key":{"shape":"S"},"value":{"shape":"S"}},
        "IntMap":{"type":"map","key":{"shape":"I"},"value":{"shape":"S"}},
        "StrList":{"type":"list","member":{"shape":"S"}},
        "Doc":{"type":"structure","members":{
          "Name":{"shape":"S"},
          "Items":{"shape":"StrList"}}},
        "PutDocReqRequest":{"type":"structure","required":["Id","Body"],
          "members":{
            "Id":{"shape":"S","location":"uri","locationName":"Id"},
            "Body":{"shape":"Doc"}},
          "payload":"Body"},
        "PutDocOptRequest":{"type":"structure","required":["Id"],
          "members":{
            "Id":{"shape":"S","location":"uri","locationName":"Id"},
            "Body":{"shape":"Doc"}},
          "payload":"Body"},
        "PutObjectRequest":{"type":"structure","required":["Bucket","Key","Body"],
          "members":{
            "Bucket":{"shape":"S","location":"uri","locationName":"Bucket"},
            "Key":{"shape":"S","location":"uri","locationName":"Key"},
            "VersionId":{"shape":"S","location":"querystring","locationName":"versionId"},
            "ContentType":{"shape":"S","location":"header","locationName":"Content-Type"},
            "Body":{"shape":"Blob"}},
          "payload":"Body"},
        "PutMetaRequest":{"type":"structure","required":["Name"],
          "members":{
            "Meta":{"shape":"StrMap","location":"headers","locationName":"x-amz-meta-"},
            "Name":{"shape":"S"},
            "Count":{"shape":"I"}}},
        "BadLabelRequest":{"type":"structure","required":["When"],
          "members":{"When":{"shape":"T","location":"uri","locationName":"When"}}},
        "BadDocRequest":{"type":"structure",
          "members":{"Items":{"shape":"IntMap"}}}
      }}"#;

    #[test]
    fn labels_query_header_payload() {
        let p = plan(M, "PutObject").unwrap();
        assert_eq!(p.method, "PUT");
        assert_eq!(p.path_template, "/b/{Bucket}/{Key+}");
        assert_eq!(p.input_shape.as_deref(), Some("PutObjectRequest"));

        // Two labels: Bucket non-greedy, Key greedy ({Key+}).
        let bucket = p.labels.iter().find(|l| l.field == "Bucket").unwrap();
        let key = p.labels.iter().find(|l| l.field == "Key").unwrap();
        assert!(!bucket.greedy);
        assert!(key.greedy);

        // Query is renamed to its wire name; header keeps its casing.
        assert_eq!(p.query.len(), 1);
        assert_eq!(p.query[0].wire, "versionId");
        assert_eq!(p.headers[0].wire, "Content-Type");

        // The blob payload is the raw body; no document members.
        assert_eq!(
            p.payload,
            Some(PayloadBind {
                field: "Body".to_string(),
                body: PayloadBody::Blob,
                optional: false,
            })
        );
        assert!(p.document.is_empty());
        assert!(!p.has_document_body());
    }

    #[test]
    fn structured_payload_required_and_optional() {
        // `Doc` has a list member, so it is serializable but NOT derivable: the
        // payload rides the explicit #424 serializer, named off the raw shape
        // (zaplang-io/zap#427). The required and optional forms differ only in
        // the `optional` flag the emitter guards the body on.
        let req = plan(M, "PutDocReq").unwrap();
        assert_eq!(
            req.payload,
            Some(PayloadBind {
                field: "Body".to_string(),
                body: PayloadBody::Document("Doc".to_string()),
                optional: false,
            })
        );
        let opt = plan(M, "PutDocOpt").unwrap();
        assert_eq!(
            opt.payload,
            Some(PayloadBind {
                field: "Body".to_string(),
                body: PayloadBody::Document("Doc".to_string()),
                optional: true,
            })
        );
    }

    #[test]
    fn prefix_headers_and_document_body() {
        let p = plan(M, "PutMeta").unwrap();
        let ph = p.prefix_headers.as_ref().unwrap();
        assert_eq!(ph.field, "Meta");
        assert_eq!(ph.prefix, "x-amz-meta-");
        assert!(ph.optional);

        // The unbound members form the JSON document body, in model order.
        assert!(p.has_document_body());
        let doc: Vec<&str> = p.document.iter().map(|m| m.field.as_str()).collect();
        assert_eq!(doc, vec!["Name", "Count"]);
        // Name is required, Count optional.
        assert!(
            !p.document
                .iter()
                .find(|m| m.field == "Name")
                .unwrap()
                .optional
        );
        assert!(
            p.document
                .iter()
                .find(|m| m.field == "Count")
                .unwrap()
                .optional
        );
    }

    #[test]
    fn enum_bound_member_is_carried_as_string() {
        let m = Model::from_json_str(
            r#"{"metadata":{"protocol":"rest-json","endpointPrefix":"svc"},
              "operations":{"Op":{"name":"Op",
                "http":{"method":"GET","requestUri":"/x"},"input":{"shape":"Req"}}},
              "shapes":{
                "E":{"type":"string","enum":["A","B"]},
                "Req":{"type":"structure","members":{
                  "V":{"shape":"E","location":"querystring","locationName":"v"}}}}}"#,
        )
        .unwrap();
        let d = compute_derivable(&m);
        let s = compute_json_serializable(&m, &d);
        let p = plan_operation(&m, &m.operations["Op"], &d, &s).unwrap();
        // The enum is bound as its plain wire string.
        assert_eq!(p.query[0].ty, ZapType::Str);
    }

    #[test]
    fn binds_bool_timestamp_and_list_query() {
        // zaplang-io/zap#425: a bool/timestamp query, a timestamp header (its
        // default format differs from a query's), and a list[str] query (repeated
        // params). A list of a non-string element stays skipped.
        let m = Model::from_json_str(
            r#"{"metadata":{"protocol":"rest-json","endpointPrefix":"svc"},
              "operations":{"Op":{"name":"Op",
                "http":{"method":"GET","requestUri":"/x"},"input":{"shape":"Req"}}},
              "shapes":{
                "S":{"type":"string"},"B":{"type":"boolean"},"T":{"type":"timestamp"},
                "SL":{"type":"list","member":{"shape":"S"}},
                "Req":{"type":"structure","members":{
                  "Flag":{"shape":"B","location":"querystring","locationName":"flag"},
                  "After":{"shape":"T","location":"querystring","locationName":"after"},
                  "Since":{"shape":"T","location":"header","locationName":"x-since"},
                  "Tags":{"shape":"SL","location":"querystring","locationName":"tag"}}}}}"#,
        )
        .unwrap();
        let d = compute_derivable(&m);
        let s = compute_json_serializable(&m, &d);
        let p = plan_operation(&m, &m.operations["Op"], &d, &s).unwrap();

        let flag = p.query.iter().find(|q| q.field == "Flag").unwrap();
        assert_eq!(flag.fmt, BindFmt::Bool);
        let after = p.query.iter().find(|q| q.field == "After").unwrap();
        assert_eq!(after.fmt, BindFmt::TsIso8601); // query default
        let since = p.headers.iter().find(|h| h.field == "Since").unwrap();
        assert_eq!(since.fmt, BindFmt::TsRfc822); // header default
                                                  // The list[str] query is a repeated-param bind, not a scalar.
        assert_eq!(p.query_lists.len(), 1);
        assert_eq!(p.query_lists[0].wire, "tag");
        assert!(!p.query.iter().any(|q| q.field == "Tags"));
    }

    #[test]
    fn timestamp_format_trait_overrides_slot_default() {
        // An explicit timestampFormat beats the slot default (epoch in a header).
        let m = Model::from_json_str(
            r#"{"metadata":{"protocol":"rest-json","endpointPrefix":"svc"},
              "operations":{"Op":{"name":"Op",
                "http":{"method":"GET","requestUri":"/x"},"input":{"shape":"Req"}}},
              "shapes":{
                "T":{"type":"timestamp"},
                "Req":{"type":"structure","members":{
                  "When":{"shape":"T","location":"header","locationName":"x-when",
                    "timestampFormat":"unixTimestamp"}}}}}"#,
        )
        .unwrap();
        let d = compute_derivable(&m);
        let s = compute_json_serializable(&m, &d);
        let p = plan_operation(&m, &m.operations["Op"], &d, &s).unwrap();
        assert_eq!(p.headers[0].fmt, BindFmt::TsEpoch);
    }

    #[test]
    fn skips_unbindable_and_non_derivable() {
        // A timestamp URI label is not bindable in v0.
        assert!(plan(M, "BadLabel").unwrap_err().contains("httpLabel"));
        // A list document member is not derive-serializable.
        assert!(plan(M, "BadDoc").unwrap_err().contains("document member"));
        // No http trait at all.
        assert!(plan(M, "NoHttp").unwrap_err().contains("http"));
    }
}
