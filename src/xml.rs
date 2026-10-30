//! rest-xml request planning.
//!
//! rest-xml (S3, CloudFront, Route53, …) is the HTTP binding layer (aws.binding,
//! zaplang-io/aws#345) with an XML document body instead of JSON — so this
//! module reuses the same URI-label / query / header / prefix-header
//! partitioning as rest-json (`binding.rs`) and differs only in the body: where
//! rest-json serializes a `@derive(Json)` struct, rest-xml builds an XML element
//! tree with the `aws.restxml` codec's primitive helpers (`rest_xml_root*`,
//! `rest_xml_scalar`, `rest_xml_struct`, `rest_xml_flat_list`,
//! `rest_xml_wrapped_list`, `rest_xml_attribute`).
//!
//! The body of a rest-xml request is the operation's `httpPayload` member when
//! it is a structure (the common case: CloudFront's `DistributionConfig`,
//! `InvalidationBatch`, …), serialized as the root element named by the member's
//! `locationName` with the member's `xmlNamespace` on it. This module walks that
//! structure recursively into an [`XmlStructPlan`] mirroring botocore's
//! `RestXMLSerializer` (botocore 1.43.121): members in model order, `xmlAttribute`
//! members onto the current element, flattened vs wrapped lists, nested
//! structures.
//!
//! v0 is deliberately conservative (same posture as the awsJson/rest-json
//! paths): an operation whose body needs something the codec cannot render yet —
//! a boolean member (the codec has no `xml_bool`), a map, a list/map of
//! non-scalars, or an XML document body with no `httpPayload` member — is
//! *skipped* with a documented reason rather than emitted wrong.

use crate::binding::{PrefixHeadersBind, ScalarBind};
use crate::model::{Model, Operation, Shape, ShapeRef, XmlNamespace};
use crate::naming::escape_ident;
use crate::types::{resolve, ZapType};

/// How a `httpPayload` member that is not a structure becomes the raw body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawKind {
    /// A `blob` member: body is `str(field)`, content type octet-stream.
    Blob,
    /// A `string` member: body is the field verbatim, content type text/plain.
    Str,
}

/// How a scalar member's value is rendered to its XML element/attribute text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlText {
    /// `input.X` verbatim (string, or an enum carried as its wire string).
    Str,
    /// `str(input.X)` (integer / long).
    Int,
    /// `str(input.X)` (float / double).
    Float,
    /// `xml_blob(input.X)` -> base64 text.
    Blob,
    /// `xml_timestamp_iso8601(input.X)`.
    TimestampIso,
    /// `xml_timestamp_epoch(input.X)`.
    TimestampEpoch,
}

/// One member of an XML structure, in model order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlMember {
    /// An `xmlAttribute` member: `attr="value"` on the enclosing element.
    Attribute {
        attr: String,
        field: String,
        text: XmlText,
        optional: bool,
    },
    /// A scalar child element `<elem>text</elem>`.
    Scalar {
        elem: String,
        field: String,
        text: XmlText,
        optional: bool,
    },
    /// A nested structure child element.
    Struct {
        elem: String,
        field: String,
        optional: bool,
        plan: XmlStructPlan,
    },
    /// A flattened list of strings: repeated `<elem>v</elem>` with no wrapper.
    FlatList {
        elem: String,
        field: String,
        optional: bool,
    },
    /// A wrapped list of strings: `<wrapper><member>v</member>…</wrapper>`.
    WrappedList {
        wrapper: String,
        member: String,
        field: String,
        optional: bool,
    },
}

/// A planned XML structure: a root/element name, an optional namespace declared
/// on it, and its members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlStructPlan {
    pub root_name: String,
    pub namespace: Option<XmlNamespace>,
    pub members: Vec<XmlMember>,
}

/// The body of a rest-xml request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlBody {
    /// No body (a GET/DELETE with everything bound to the URI/query/headers).
    Empty,
    /// A raw `httpPayload` blob/string member carried verbatim.
    Raw {
        field: String,
        kind: RawKind,
        optional: bool,
    },
    /// A `httpPayload` structure member serialized as the XML document body.
    Struct { field: String, plan: XmlStructPlan },
}

/// The full rest-xml plan for one operation: the binding (shared with
/// rest-json) plus the XML body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestXmlOp {
    pub method: String,
    pub path_template: String,
    pub input_shape: Option<String>,
    pub labels: Vec<ScalarBind>,
    pub query: Vec<ScalarBind>,
    pub headers: Vec<ScalarBind>,
    pub prefix_headers: Option<PrefixHeadersBind>,
    pub body: XmlBody,
}

/// A scalar type bindable to a URI/query/header slot (same rule as rest-json).
fn is_bindable_scalar(ty: &ZapType) -> bool {
    matches!(ty, ZapType::Str | ZapType::Enum(_) | ZapType::Int)
}

/// The generated field type for a bound slot: an enum is carried as its plain
/// wire `str`, everything else keeps its type.
fn bound_wire_type(ty: &ZapType) -> ZapType {
    match ty {
        ZapType::Enum(_) => ZapType::Str,
        other => other.clone(),
    }
}

/// The XML text encoding for a resolved scalar type, or `None` when it is not a
/// scalar the codec can render (a boolean — the codec has no `xml_bool` — or a
/// non-scalar), so the caller skips the operation.
fn xml_text(ty: &ZapType, r: &ShapeRef, shape: Option<&Shape>) -> Option<XmlText> {
    match ty {
        ZapType::Str | ZapType::Enum(_) => Some(XmlText::Str),
        ZapType::Int => Some(XmlText::Int),
        ZapType::Float => Some(XmlText::Float),
        ZapType::Bytes => Some(XmlText::Blob),
        ZapType::DateTime => {
            let fmt = r
                .timestamp_format
                .as_deref()
                .or_else(|| shape.and_then(|s| s.timestamp_format.as_deref()));
            match fmt {
                Some("unixTimestamp") | Some("epoch-seconds") => Some(XmlText::TimestampEpoch),
                _ => Some(XmlText::TimestampIso),
            }
        }
        // Bool has no codec helper; Struct/List/Dict are not scalars.
        _ => None,
    }
}

/// Plan a structure as an XML element named `root_name`, with the namespace from
/// `member_ref` (the member referencing this structure) falling back to the
/// shape's own. Recurses into nested structures. Returns a skip reason on any
/// member the codec cannot serialize in v0.
fn plan_xml_struct(
    model: &Model,
    shape_name: &str,
    member_ref: Option<&ShapeRef>,
    root_name: &str,
) -> Result<XmlStructPlan, String> {
    let shape = model
        .shape(shape_name)
        .filter(|s| s.is_structure())
        .ok_or_else(|| format!("XML body shape `{shape_name}` is not a structure"))?;

    let namespace = member_ref
        .and_then(|r| r.xml_namespace.clone())
        .or_else(|| shape.xml_namespace.clone());

    let mut members = Vec::new();
    for (mn, r) in &shape.members {
        let field = escape_ident(mn).0;
        let elem = r.xml_wire_name(mn).to_string();
        let optional = !shape.required.contains(mn);
        let ty = resolve(model, &r.shape);
        let member_shape = model.shape(&r.shape);

        if r.xml_attribute {
            // xmlAttribute members must be scalar strings (an attribute value is
            // text); botocore requires a serialization name, which `elem` is.
            match xml_text(&ty, r, member_shape) {
                Some(text @ (XmlText::Str | XmlText::Int | XmlText::Float)) => {
                    members.push(XmlMember::Attribute {
                        attr: elem,
                        field,
                        text,
                        optional,
                    });
                }
                _ => {
                    return Err(format!(
                        "xmlAttribute member `{mn}` is not a string/number scalar"
                    ))
                }
            }
            continue;
        }

        match &ty {
            ZapType::Struct(_) => {
                let plan = plan_xml_struct(model, &r.shape, Some(r), &elem)?;
                members.push(XmlMember::Struct {
                    elem,
                    field,
                    optional,
                    plan,
                });
            }
            ZapType::List(inner) => {
                if !matches!(**inner, ZapType::Str | ZapType::Enum(_)) {
                    return Err(format!(
                        "member `{mn}` is a list of {} (only string lists in v0)",
                        inner.render()
                    ));
                }
                let flattened = r.flattened || member_shape.map(|s| s.flattened).unwrap_or(false);
                if flattened {
                    members.push(XmlMember::FlatList {
                        elem,
                        field,
                        optional,
                    });
                } else {
                    let member_seg = member_shape
                        .and_then(|s| s.member.as_ref())
                        .map(|m| m.xml_wire_name("member").to_string())
                        .unwrap_or_else(|| "member".to_string());
                    members.push(XmlMember::WrappedList {
                        wrapper: elem,
                        member: member_seg,
                        field,
                        optional,
                    });
                }
            }
            ZapType::Dict(..) => {
                return Err(format!(
                    "member `{mn}` is a map (rest-xml maps are a v0 follow-up)"
                ));
            }
            scalar => {
                let text = xml_text(scalar, r, member_shape).ok_or_else(|| {
                    if *scalar == ZapType::Bool {
                        format!("member `{mn}` is a bool (the codec has no xml_bool yet)")
                    } else {
                        format!("member `{mn}` has unsupported type {}", scalar.render())
                    }
                })?;
                members.push(XmlMember::Scalar {
                    elem,
                    field,
                    text,
                    optional,
                });
            }
        }
    }

    Ok(XmlStructPlan {
        root_name: root_name.to_string(),
        namespace,
        members,
    })
}

/// Plan the rest-xml request for `op`, or a short reason it must be skipped.
pub fn plan_rest_xml(model: &Model, op: &Operation) -> Result<RestXmlOp, String> {
    let http = op
        .http
        .as_ref()
        .ok_or("operation has no `http` trait (not a REST operation)")?;
    if http.method.is_empty() || http.request_uri.is_empty() {
        return Err("`http` trait is missing a method or requestUri".to_string());
    }

    let mut plan = RestXmlOp {
        method: http.method.clone(),
        path_template: http.request_uri.clone(),
        input_shape: None,
        labels: Vec::new(),
        query: Vec::new(),
        headers: Vec::new(),
        prefix_headers: None,
        body: XmlBody::Empty,
    };

    let input_ref = match op.input.as_ref() {
        Some(r) => r,
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
    let mut document_members: Vec<String> = Vec::new();

    for (mn, r) in &input.members {
        let field = escape_ident(mn).0;
        let wire = r.wire_name(mn).to_string();
        let ty = resolve(model, &r.shape);
        let optional = !input.required.contains(mn);

        if payload_member == Some(mn.as_str()) {
            match &ty {
                ZapType::Bytes => {
                    plan.body = XmlBody::Raw {
                        field,
                        kind: RawKind::Blob,
                        optional,
                    }
                }
                ZapType::Str => {
                    plan.body = XmlBody::Raw {
                        field,
                        kind: RawKind::Str,
                        optional,
                    }
                }
                ZapType::Struct(_) => {
                    if optional {
                        return Err(format!(
                            "httpPayload structure `{mn}` is optional (v0 needs a required body)"
                        ));
                    }
                    let root = r.xml_wire_name(mn).to_string();
                    let struct_plan = plan_xml_struct(model, &r.shape, Some(r), &root)?;
                    plan.body = XmlBody::Struct {
                        field,
                        plan: struct_plan,
                    };
                }
                other => {
                    return Err(format!(
                        "httpPayload member `{mn}` has unsupported type {}",
                        other.render()
                    ))
                }
            }
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
                plan.labels.push(ScalarBind {
                    field,
                    wire: wire.clone(),
                    greedy: http.label_is_greedy(&wire),
                    ty: bound_wire_type(&ty),
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
                    ty: bound_wire_type(&ty),
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
                    ty: bound_wire_type(&ty),
                    optional,
                    greedy: false,
                    member: mn.clone(),
                });
            }
            Some("headers") => match &ty {
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
            },
            Some("statusCode") => {}
            Some(other) => return Err(format!("member `{mn}` has unknown location `{other}`")),
            None => document_members.push(mn.clone()),
        }
    }

    // An unbound member with no httpPayload would be an XML document body rooted
    // at the input shape — not supported in v0 (CloudFront always uses a
    // payload; S3's document-body ops are #356's concern).
    if payload_member.is_none() && !document_members.is_empty() {
        return Err(format!(
            "rest-xml document body without httpPayload (members {}) is a v0 follow-up",
            document_members.join(", ")
        ));
    }

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op<'a>(m: &'a Model, name: &str) -> &'a Operation {
        &m.operations[name]
    }

    // A synthetic rest-xml service: a payload structure with a default
    // namespace, a nested struct, a wrapped list, a flattened list, an
    // xmlAttribute, and a bool member op that must be skipped.
    const M: &str = r#"{
      "metadata":{"protocol":"rest-xml","endpointPrefix":"svc","serviceId":"Svc","apiVersion":"2021-01-01"},
      "operations":{
        "PutThing":{"name":"PutThing","http":{"method":"PUT","requestUri":"/thing/{Id}"},
          "input":{"shape":"PutThingRequest"}},
        "BadBool":{"name":"BadBool","http":{"method":"PUT","requestUri":"/b"},
          "input":{"shape":"BadBoolRequest"}}
      },
      "shapes":{
        "S":{"type":"string"},
        "I":{"type":"integer"},
        "B":{"type":"boolean"},
        "TagList":{"type":"list","member":{"shape":"S","locationName":"Tag"}},
        "AliasList":{"type":"list","member":{"shape":"S"},"flattened":true},
        "Owner":{"type":"structure","members":{"Id":{"shape":"S"}}},
        "Config":{"type":"structure","required":["Name"],
          "xmlNamespace":{"uri":"urn:svc"},
          "members":{
            "Version":{"shape":"S","xmlAttribute":true,"locationName":"version"},
            "Name":{"shape":"S"},
            "Owner":{"shape":"Owner"},
            "Tags":{"shape":"TagList"},
            "Alias":{"shape":"AliasList"}}},
        "PutThingRequest":{"type":"structure","required":["Id","Config"],
          "members":{
            "Id":{"shape":"S","location":"uri","locationName":"Id"},
            "Config":{"shape":"Config","locationName":"Config"}},
          "payload":"Config"},
        "BadBoolRequest":{"type":"structure","required":["Flag"],
          "members":{"Flag":{"shape":"B"}},"payload":"Flag"}
      }}"#;

    #[test]
    fn plans_namespace_attribute_nested_and_lists() {
        let m = Model::from_json_str(M).unwrap();
        let p = plan_rest_xml(&m, op(&m, "PutThing")).unwrap();
        assert_eq!(p.method, "PUT");
        assert_eq!(p.labels.len(), 1);
        assert_eq!(p.labels[0].wire, "Id");

        let (field, plan) = match &p.body {
            XmlBody::Struct { field, plan } => (field, plan),
            other => panic!("expected a struct body, got {other:?}"),
        };
        assert_eq!(field, "Config");
        assert_eq!(plan.root_name, "Config");
        assert_eq!(plan.namespace.as_ref().unwrap().uri, "urn:svc");
        assert!(plan.namespace.as_ref().unwrap().prefix.is_none());

        // Members in model order: attribute, scalar, nested struct, wrapped
        // list, flattened list.
        assert!(matches!(&plan.members[0], XmlMember::Attribute { attr, .. } if attr == "version"));
        assert!(matches!(&plan.members[1], XmlMember::Scalar { elem, .. } if elem == "Name"));
        match &plan.members[2] {
            XmlMember::Struct { elem, plan, .. } => {
                assert_eq!(elem, "Owner");
                assert!(matches!(&plan.members[0], XmlMember::Scalar { elem, .. } if elem == "Id"));
            }
            other => panic!("expected nested struct, got {other:?}"),
        }
        match &plan.members[3] {
            XmlMember::WrappedList {
                wrapper, member, ..
            } => {
                assert_eq!(wrapper, "Tags");
                assert_eq!(member, "Tag");
            }
            other => panic!("expected wrapped list, got {other:?}"),
        }
        assert!(matches!(&plan.members[4], XmlMember::FlatList { elem, .. } if elem == "Alias"));
    }

    #[test]
    fn bool_body_member_is_skipped() {
        // A struct payload with a bool member hits the xml_bool skip (the codec
        // has no boolean text helper yet).
        let m2 = Model::from_json_str(
            r#"{"metadata":{"protocol":"rest-xml","endpointPrefix":"svc"},
              "operations":{"Op":{"name":"Op","http":{"method":"PUT","requestUri":"/x"},
                "input":{"shape":"Req"}}},
              "shapes":{
                "B":{"type":"boolean"},
                "Body":{"type":"structure","required":["Flag"],"members":{"Flag":{"shape":"B"}}},
                "Req":{"type":"structure","required":["Body"],
                  "members":{"Body":{"shape":"Body","locationName":"Body"}},"payload":"Body"}}}"#,
        )
        .unwrap();
        let err = plan_rest_xml(&m2, op(&m2, "Op")).unwrap_err();
        assert!(err.contains("xml_bool"), "{err}");
    }
}
