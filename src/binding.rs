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
    /// A derivable `structure` member: the body is `field.to_json()`, content
    /// type `application/json`.
    Document,
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

/// A scalar type the binding layer can render into a path/query/header slot: a
/// string, an open-enum (sent as its plain wire string), or an integer the
/// emitter coerces with `str(...)`. Floats and bools are skipped in v0 (their
/// Zap `str(...)` spelling does not match the AWS wire form — e.g. `True` vs
/// `true`); timestamps, blobs and collections need member-specific wire
/// formatting and are skipped too.
fn is_bindable_scalar(ty: &ZapType) -> bool {
    matches!(ty, ZapType::Str | ZapType::Enum(_) | ZapType::Int)
}

/// The type the generated input field takes for a bound scalar slot: a string
/// enum is carried as its plain wire `str`, everything else keeps its type.
fn wire_type(ty: &ZapType) -> ZapType {
    match ty {
        ZapType::Enum(_) => ZapType::Str,
        other => other.clone(),
    }
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
                ZapType::Struct(n) if *derivable.get(n).unwrap_or(&false) => PayloadBody::Document,
                ZapType::Struct(_) => {
                    return Err(format!(
                        "httpPayload member `{mn}` is a non-derivable structure"
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
                if !is_bindable_scalar(&ty) {
                    return Err(format!(
                        "httpLabel `{mn}` has unsupported type {}",
                        ty.render()
                    ));
                }
                let greedy = http.label_is_greedy(&wire);
                plan.labels.push(ScalarBind {
                    field,
                    wire,
                    greedy,
                    ty: wire_type(&ty),
                    optional,
                    member: mn.clone(),
                });
            }
            Some("querystring") => {
                if !is_bindable_scalar(&ty) {
                    return Err(format!(
                        "httpQuery `{mn}` has unsupported type {}",
                        ty.render()
                    ));
                }
                plan.query.push(ScalarBind {
                    field,
                    wire,
                    ty: wire_type(&ty),
                    optional,
                    greedy: false,
                    member: mn.clone(),
                });
            }
            Some("header") => {
                if !is_bindable_scalar(&ty) {
                    return Err(format!(
                        "httpHeader `{mn}` has unsupported type {}",
                        ty.render()
                    ));
                }
                plan.headers.push(ScalarBind {
                    field,
                    wire,
                    ty: wire_type(&ty),
                    optional,
                    greedy: false,
                    member: mn.clone(),
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
        "NoHttp":{"name":"NoHttp","input":{"shape":"BadDocRequest"}}
      },
      "shapes":{
        "S":{"type":"string"},
        "I":{"type":"integer"},
        "T":{"type":"timestamp"},
        "Blob":{"type":"blob"},
        "StrMap":{"type":"map","key":{"shape":"S"},"value":{"shape":"S"}},
        "IntMap":{"type":"map","key":{"shape":"I"},"value":{"shape":"S"}},
        "StrList":{"type":"list","member":{"shape":"S"}},
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
    fn skips_unbindable_and_non_derivable() {
        // A timestamp URI label is not bindable in v0.
        assert!(plan(M, "BadLabel").unwrap_err().contains("httpLabel"));
        // A list document member is not derive-serializable.
        assert!(plan(M, "BadDoc").unwrap_err().contains("document member"));
        // No http trait at all.
        assert!(plan(M, "NoHttp").unwrap_err().contains("http"));
    }
}
