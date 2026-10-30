//! rest-xml request planning.
//!
//! rest-xml (S3, CloudFront, Route53, S3Control) is the HTTP binding layer
//! (aws.binding, zaplang-io/aws#345) with an XML document body instead of JSON —
//! so this module reuses the same URI-label / query / header / prefix-header
//! partitioning as rest-json (`binding.rs`) and differs only in the body: where
//! rest-json serializes a `@derive(Json)` struct, rest-xml builds an XML element
//! tree with the `aws.restxml` codec's primitive helpers (`rest_xml_root*`,
//! `rest_xml_scalar`, `rest_xml_struct`, `rest_xml_flat_list`,
//! `rest_xml_wrapped_list`, `rest_xml_attribute`).
//!
//! The body of a rest-xml request is either the operation's `httpPayload`
//! structure member (CloudFront's `DistributionConfig`, …), serialized as the
//! root element named by the member's `locationName` with the member's
//! `xmlNamespace`, or — when there is no `httpPayload` — an *implicit document
//! body* built from the operation's unbound (document) members, rooted at the
//! operation `input` ref's `locationName` + `xmlNamespace` (Route53 / S3Control).
//! This module walks that structure recursively into an [`XmlStructPlan`]
//! mirroring botocore's `RestXMLSerializer` (botocore 1.43.121): members in model
//! order, `xmlAttribute` members onto the current element, flattened vs wrapped
//! lists / maps, nested structures, lists/maps of structures, and booleans.
//!
//! #426 lifts the #354 v0 (flat scalar + scalar-list bodies only) to booleans,
//! maps, lists/maps of structures, and the implicit document body. A member the
//! generator still cannot serialize byte-faithfully — a non-string scalar
//! carrying its own `xmlNamespace`, a list/map of lists/maps, or a recursive
//! shape graph — makes the operation *skipped* with a documented reason rather
//! than emitting wrong output.

use crate::binding::{
    query_list_elem_ok, scalar_bind_fmt, PrefixHeadersBind, QueryListBind, ScalarBind, Slot,
};
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
    /// A boolean, via the per-file `_xml_bool` helper -> "true"/"false".
    Bool,
    /// `xml_blob(input.X)` -> base64 text.
    Blob,
    /// `xml_timestamp_iso8601(input.X)`.
    TimestampIso,
    /// `xml_timestamp_epoch(input.X)`.
    TimestampEpoch,
}

/// A value position (a list element or a map value): a scalar or a structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlValue {
    Scalar(XmlText),
    Struct(XmlStructPlan),
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
    /// A flattened list of strings: repeated `<elem>v</elem>` with no wrapper
    /// (codec helper; unchanged from #354).
    FlatList {
        elem: String,
        field: String,
        optional: bool,
    },
    /// A wrapped list of strings: `<wrapper><member>v</member>…</wrapper>` (codec
    /// helper; unchanged from #354).
    WrappedList {
        wrapper: String,
        member: String,
        field: String,
        optional: bool,
    },
    /// A list of non-string elements (a non-string scalar or a structure),
    /// emitted with an explicit loop. `wrapper` is the enclosing element for a
    /// wrapped list (None when flattened); `item_elem` is each item's tag.
    List {
        field: String,
        optional: bool,
        wrapper: Option<String>,
        item_elem: String,
        value: Box<XmlValue>,
    },
    /// A map, wrapped (`<name><entry><key/><value/></entry>…</name>`) or
    /// flattened (`<name><key/><value/></name>` repeated). Keys emitted sorted.
    Map {
        field: String,
        optional: bool,
        flattened: bool,
        name: String,
        key_name: String,
        value_name: String,
        value: Box<XmlValue>,
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
    /// When `optional`, an absent member sends no body at all (zaplang-io/zap#427).
    Struct {
        field: String,
        optional: bool,
        plan: XmlStructPlan,
    },
    /// An implicit XML document body built from the operation's unbound
    /// (document) members (no `httpPayload`): read off `input` directly, rooted
    /// at the `input` ref's name + namespace (Route53 / S3Control).
    Document { plan: XmlStructPlan },
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
    /// List members bound to `httpQuery`, emitted as repeated query parameters
    /// (zaplang-io/zap#425).
    pub query_lists: Vec<QueryListBind>,
    pub headers: Vec<ScalarBind>,
    pub prefix_headers: Option<PrefixHeadersBind>,
    pub body: XmlBody,
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
/// scalar (a non-scalar type).
fn xml_text(ty: &ZapType, r: &ShapeRef, shape: Option<&Shape>) -> Option<XmlText> {
    match ty {
        ZapType::Str | ZapType::Enum(_) => Some(XmlText::Str),
        ZapType::Int => Some(XmlText::Int),
        ZapType::Float => Some(XmlText::Float),
        ZapType::Bool => Some(XmlText::Bool),
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
        _ => None,
    }
}

/// Plan a value position (list element or map value) as a scalar or structure,
/// or a skip reason. Recurses into a nested structure, guarding cycles.
fn plan_xml_value(
    model: &Model,
    r: &ShapeRef,
    elem_name: &str,
    stack: &mut Vec<String>,
) -> Result<XmlValue, String> {
    let ty = resolve(model, &r.shape);
    let member_shape = model.shape(&r.shape);
    match &ty {
        ZapType::Struct(_) => {
            let plan = plan_xml_struct(model, &r.shape, Some(r), elem_name, stack)?;
            Ok(XmlValue::Struct(plan))
        }
        ZapType::List(_) | ZapType::Dict(..) => {
            Err("a list/map of lists/maps (not representable in v0)".to_string())
        }
        scalar => {
            let text = xml_text(scalar, r, member_shape)
                .ok_or_else(|| format!("unsupported element type {}", scalar.render()))?;
            Ok(XmlValue::Scalar(text))
        }
    }
}

/// Plan the member list of an XML structure (shared by a payload structure, a
/// nested structure, and the implicit document body). `members`/`required` are
/// the members to serialize, in order.
fn plan_xml_members(
    model: &Model,
    members: &[(&String, &ShapeRef)],
    required: &[String],
    stack: &mut Vec<String>,
) -> Result<Vec<XmlMember>, String> {
    let mut out = Vec::new();
    for (mn, r) in members {
        let mn = *mn;
        let field = escape_ident(mn).0;
        let elem = r.xml_wire_name(mn).to_string();
        let optional = !required.contains(mn);
        let ty = resolve(model, &r.shape);
        let member_shape = model.shape(&r.shape);

        if r.xml_attribute {
            match xml_text(&ty, r, member_shape) {
                Some(text @ (XmlText::Str | XmlText::Int | XmlText::Float)) => {
                    out.push(XmlMember::Attribute {
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
                let plan = plan_xml_struct(model, &r.shape, Some(r), &elem, stack)?;
                out.push(XmlMember::Struct {
                    elem,
                    field,
                    optional,
                    plan,
                });
            }
            ZapType::List(inner) => {
                let flattened = r.flattened || member_shape.map(|s| s.flattened).unwrap_or(false);
                let member_seg = member_shape
                    .and_then(|s| s.member.as_ref())
                    .map(|m| m.xml_wire_name("member").to_string())
                    .unwrap_or_else(|| "member".to_string());
                if matches!(**inner, ZapType::Str | ZapType::Enum(_)) {
                    // Preserve the #354 scalar-list emission (codec helpers).
                    if flattened {
                        out.push(XmlMember::FlatList {
                            elem,
                            field,
                            optional,
                        });
                    } else {
                        out.push(XmlMember::WrappedList {
                            wrapper: elem,
                            member: member_seg,
                            field,
                            optional,
                        });
                    }
                    continue;
                }
                // Non-string element: an explicit loop. Wrapped lists nest the
                // items under `<elem>` with each item tagged `member_seg`;
                // flattened lists repeat `<elem>` on the parent.
                let elem_ref = member_shape
                    .and_then(|s| s.member.clone())
                    .ok_or_else(|| format!("list member `{mn}` has no element shape"))?;
                let (wrapper, item_elem) = if flattened {
                    (None, elem.clone())
                } else {
                    (Some(elem.clone()), member_seg)
                };
                let value = plan_xml_value(model, &elem_ref, &item_elem, stack)?;
                out.push(XmlMember::List {
                    field,
                    optional,
                    wrapper,
                    item_elem,
                    value: Box::new(value),
                });
            }
            ZapType::Dict(k, _) => {
                if **k != ZapType::Str && !matches!(**k, ZapType::Enum(_)) {
                    return Err(format!("map member `{mn}` has a non-string key"));
                }
                let flattened = r.flattened || member_shape.map(|s| s.flattened).unwrap_or(false);
                let key_ref = member_shape.and_then(|s| s.key.as_ref());
                let val_ref = member_shape
                    .and_then(|s| s.value.clone())
                    .ok_or_else(|| format!("map member `{mn}` has no value shape"))?;
                let key_name = key_ref
                    .map(|kr| kr.xml_wire_name("key").to_string())
                    .unwrap_or_else(|| "key".to_string());
                let value_name = val_ref.xml_wire_name("value").to_string();
                let value = plan_xml_value(model, &val_ref, &value_name, stack)?;
                out.push(XmlMember::Map {
                    field,
                    optional,
                    flattened,
                    name: elem,
                    key_name,
                    value_name,
                    value: Box::new(value),
                });
            }
            scalar => {
                // A scalar member carrying its own xmlNamespace would need the ns
                // on its element; the codec's scalar helper does not add one, so
                // skip rather than drop the namespace. (Vanishingly rare.)
                if r.xml_namespace.is_some() {
                    return Err(format!("scalar member `{mn}` carries an xmlNamespace"));
                }
                let text = xml_text(scalar, r, member_shape).ok_or_else(|| {
                    format!("member `{mn}` has unsupported type {}", scalar.render())
                })?;
                out.push(XmlMember::Scalar {
                    elem,
                    field,
                    text,
                    optional,
                });
            }
        }
    }
    Ok(out)
}

/// Plan a structure as an XML element named `root_name`, namespace from
/// `member_ref` falling back to the shape's own. Recurses, guarding cycles via
/// `stack` (the shape names currently being planned).
fn plan_xml_struct(
    model: &Model,
    shape_name: &str,
    member_ref: Option<&ShapeRef>,
    root_name: &str,
    stack: &mut Vec<String>,
) -> Result<XmlStructPlan, String> {
    let shape = model
        .shape(shape_name)
        .filter(|s| s.is_structure())
        .ok_or_else(|| format!("XML body shape `{shape_name}` is not a structure"))?;

    if stack.iter().any(|s| s == shape_name) {
        return Err(format!("recursive XML shape `{shape_name}`"));
    }
    stack.push(shape_name.to_string());

    let namespace = member_ref
        .and_then(|r| r.xml_namespace.clone())
        .or_else(|| shape.xml_namespace.clone());

    let members: Vec<(&String, &ShapeRef)> = shape.members.iter().collect();
    let result = plan_xml_members(model, &members, &shape.required, stack);
    stack.pop();
    let members = result?;

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
        query_lists: Vec::new(),
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
    let mut document_members: Vec<(&String, &ShapeRef)> = Vec::new();

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
                    // An optional structure payload is no longer skipped: an
                    // absent member just sends no body (zaplang-io/zap#427).
                    let root = r.xml_wire_name(mn).to_string();
                    let mut stack = Vec::new();
                    let struct_plan = plan_xml_struct(model, &r.shape, Some(r), &root, &mut stack)?;
                    plan.body = XmlBody::Struct {
                        field,
                        optional,
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
                let fmt = scalar_bind_fmt(model, r, &ty, Slot::Label).ok_or_else(|| {
                    format!("httpLabel `{mn}` has unsupported type {}", ty.render())
                })?;
                plan.labels.push(ScalarBind {
                    field,
                    wire: wire.clone(),
                    greedy: http.label_is_greedy(&wire),
                    ty: bound_wire_type(&ty),
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
                        ty: bound_wire_type(&ty),
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
                    ty: bound_wire_type(&ty),
                    optional,
                    greedy: false,
                    member: mn.clone(),
                    fmt,
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
            None => document_members.push((mn, r)),
        }
    }

    // No httpPayload but unbound members -> an implicit XML document body rooted
    // at the operation `input` ref's locationName + xmlNamespace (Route53 /
    // S3Control build the body from top-level members this way).
    if payload_member.is_none() && !document_members.is_empty() {
        let root = input_ref
            .location_name
            .as_deref()
            .unwrap_or(&input_ref.shape)
            .to_string();
        let namespace = input_ref
            .xml_namespace
            .clone()
            .or_else(|| input.xml_namespace.clone());
        let mut stack = vec![input_ref.shape.clone()];
        let members = plan_xml_members(model, &document_members, &input.required, &mut stack)?;
        plan.body = XmlBody::Document {
            plan: XmlStructPlan {
                root_name: root,
                namespace,
                members,
            },
        };
    }

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op<'a>(m: &'a Model, name: &str) -> &'a Operation {
        &m.operations[name]
    }

    const M: &str = r#"{
      "metadata":{"protocol":"rest-xml","endpointPrefix":"svc","serviceId":"Svc","apiVersion":"2021-01-01"},
      "operations":{
        "PutThing":{"name":"PutThing","http":{"method":"PUT","requestUri":"/thing/{Id}"},
          "input":{"shape":"PutThingRequest"}},
        "BoolOp":{"name":"BoolOp","http":{"method":"PUT","requestUri":"/b"},
          "input":{"shape":"BoolRequest"}},
        "PutThingOpt":{"name":"PutThingOpt","http":{"method":"PUT","requestUri":"/thing/{Id}"},
          "input":{"shape":"PutThingOptRequest"}}
      },
      "shapes":{
        "S":{"type":"string"},
        "B":{"type":"boolean"},
        "TagList":{"type":"list","member":{"shape":"S","locationName":"Tag"}},
        "AliasList":{"type":"list","member":{"shape":"S"},"flattened":true},
        "Owner":{"type":"structure","members":{"Id":{"shape":"S"}}},
        "OwnerList":{"type":"list","member":{"shape":"Owner","locationName":"Owner"}},
        "StrMap":{"type":"map","key":{"shape":"S"},"value":{"shape":"S"}},
        "Config":{"type":"structure","required":["Name"],
          "xmlNamespace":{"uri":"urn:svc"},
          "members":{
            "Version":{"shape":"S","xmlAttribute":true,"locationName":"version"},
            "Name":{"shape":"S"},
            "Enabled":{"shape":"B"},
            "Owner":{"shape":"Owner"},
            "Owners":{"shape":"OwnerList"},
            "Attrs":{"shape":"StrMap"},
            "Tags":{"shape":"TagList"},
            "Alias":{"shape":"AliasList"}}},
        "PutThingRequest":{"type":"structure","required":["Id","Config"],
          "members":{
            "Id":{"shape":"S","location":"uri","locationName":"Id"},
            "Config":{"shape":"Config","locationName":"Config"}},
          "payload":"Config"},
        "BoolRequest":{"type":"structure","required":["Flag"],
          "members":{"Flag":{"shape":"B"}},"payload":"Flag"},
        "PutThingOptRequest":{"type":"structure","required":["Id"],
          "members":{
            "Id":{"shape":"S","location":"uri","locationName":"Id"},
            "Config":{"shape":"Config","locationName":"Config"}},
          "payload":"Config"}
      }}"#;

    #[test]
    fn plans_bool_nested_structlist_and_map() {
        let m = Model::from_json_str(M).unwrap();
        let p = plan_rest_xml(&m, op(&m, "PutThing")).unwrap();
        let plan = match &p.body {
            XmlBody::Struct { plan, .. } => plan,
            other => panic!("expected struct body, got {other:?}"),
        };
        assert_eq!(plan.root_name, "Config");
        assert_eq!(plan.namespace.as_ref().unwrap().uri, "urn:svc");
        // version attr, Name scalar, Enabled bool, Owner struct, Owners
        // list-of-struct, Attrs map, Tags wrapped str-list, Alias flat str-list.
        assert!(matches!(&plan.members[0], XmlMember::Attribute { .. }));
        assert!(matches!(
            &plan.members[1],
            XmlMember::Scalar {
                text: XmlText::Str,
                ..
            }
        ));
        assert!(matches!(
            &plan.members[2],
            XmlMember::Scalar {
                text: XmlText::Bool,
                ..
            }
        ));
        assert!(matches!(&plan.members[3], XmlMember::Struct { .. }));
        match &plan.members[4] {
            XmlMember::List {
                wrapper,
                item_elem,
                value,
                ..
            } => {
                assert_eq!(wrapper.as_deref(), Some("Owners"));
                assert_eq!(item_elem, "Owner");
                assert!(matches!(**value, XmlValue::Struct(_)));
            }
            other => panic!("expected list of structs, got {other:?}"),
        }
        match &plan.members[5] {
            XmlMember::Map {
                name,
                key_name,
                value_name,
                flattened,
                ..
            } => {
                assert_eq!(name, "Attrs");
                assert_eq!(key_name, "key");
                assert_eq!(value_name, "value");
                assert!(!flattened);
            }
            other => panic!("expected map, got {other:?}"),
        }
        assert!(matches!(&plan.members[6], XmlMember::WrappedList { .. }));
        assert!(matches!(&plan.members[7], XmlMember::FlatList { .. }));
    }

    #[test]
    fn optional_struct_payload_is_planned_not_skipped() {
        // A required struct payload plans a non-optional body; the same payload
        // made optional plans the identical struct with `optional: true` (an
        // absent body is emitted by the emitter, zaplang-io/zap#427) — no longer
        // skipped.
        let m = Model::from_json_str(M).unwrap();
        let req = plan_rest_xml(&m, op(&m, "PutThing")).unwrap();
        match &req.body {
            XmlBody::Struct { optional, plan, .. } => {
                assert!(!optional);
                assert_eq!(plan.root_name, "Config");
            }
            other => panic!("expected struct body, got {other:?}"),
        }
        let opt = plan_rest_xml(&m, op(&m, "PutThingOpt")).unwrap();
        match &opt.body {
            XmlBody::Struct { optional, plan, .. } => {
                assert!(optional);
                assert_eq!(plan.root_name, "Config");
            }
            other => panic!("expected struct body, got {other:?}"),
        }
    }

    const IMPL: &str = r#"{
      "metadata":{"protocol":"rest-xml","endpointPrefix":"r53","serviceId":"R53","apiVersion":"2013-04-01"},
      "operations":{
        "ChangeThing":{"name":"ChangeThing","http":{"method":"POST","requestUri":"/2013/thing"},
          "input":{"shape":"ChangeRequest","locationName":"ChangeRequest",
            "xmlNamespace":{"uri":"https://route53.amazonaws.com/doc/2013-04-01/"}}}
      },
      "shapes":{
        "S":{"type":"string"},
        "Batch":{"type":"structure","required":["Comment"],"members":{"Comment":{"shape":"S"}}},
        "ChangeRequest":{"type":"structure","required":["ChangeBatch"],
          "members":{"ChangeBatch":{"shape":"Batch"}}}
      }}"#;

    #[test]
    fn plans_implicit_document_body() {
        let m = Model::from_json_str(IMPL).unwrap();
        let p = plan_rest_xml(&m, op(&m, "ChangeThing")).unwrap();
        let plan = match &p.body {
            XmlBody::Document { plan } => plan,
            other => panic!("expected implicit document body, got {other:?}"),
        };
        assert_eq!(plan.root_name, "ChangeRequest");
        assert_eq!(
            plan.namespace.as_ref().unwrap().uri,
            "https://route53.amazonaws.com/doc/2013-04-01/"
        );
        assert!(
            matches!(&plan.members[0], XmlMember::Struct { elem, .. } if elem == "ChangeBatch")
        );
    }
}
