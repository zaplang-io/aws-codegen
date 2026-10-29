//! query + ec2 protocol serialization planning.
//!
//! The `query` protocol (IAM, STS, SNS, SimpleDB, …) and its `ec2` variant POST
//! the whole input as a flat `application/x-www-form-urlencoded` body — no URI /
//! query / header binding — with the operation chosen by an `Action` parameter
//! and the model pinned by a `Version` parameter. This module partitions an
//! operation's input members into the form parameters the hand-written
//! `aws.query` codec (zaplang-io/aws#353) serializes, mapping each member to one
//! deterministic key convention:
//!
//!   * a scalar  -> `query_scalar(p, Key, text)`;
//!   * a bool / blob / timestamp -> `query_scalar` over the codec's text helper;
//!   * a list of scalars -> `query_flat_list` (flattened lists and every ec2
//!     list: `Name.N`) or `query_list` (wrapped: `Name.member.N`).
//!
//! The only difference between the two flavors is the member *key*: `query`
//! uses the member's `locationName` (else its name); `ec2` uses its `queryName`,
//! else the capitalized `locationName`, else its name — and ec2 lists are always
//! flattened. This mirrors botocore's `QuerySerializer` / `EC2Serializer`
//! (botocore 1.43.121), which the oracle codec was cross-checked against.
//!
//! The analysis is conservative, like the awsJson/rest-json paths: a member the
//! codec cannot serialize yet (a nested structure, a list/map of non-scalars, a
//! map — all follow-ups) makes the whole operation *skipped* with a documented
//! reason rather than emitting a body that would not match the oracle.

use crate::model::{Model, Operation};
use crate::naming::escape_ident;
use crate::types::{resolve, ZapType};

/// The query flavor: plain `query` (awsQuery) or the `ec2` key variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryFlavor {
    Query,
    Ec2,
}

/// How a member's value is rendered to its form-parameter text (the codec's
/// scalar text helpers). A string/enum passes through; the rest wrap a helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalarText {
    /// `input.X` verbatim (string, or an enum carried as its wire string).
    Str,
    /// `str(input.X)` (an integer / long).
    Int,
    /// `str(input.X)` (a float / double — same Zap spelling).
    Float,
    /// `query_bool(input.X)` -> "true"/"false".
    Bool,
    /// `query_blob(input.X)` -> base64 text.
    Blob,
    /// `query_timestamp_iso8601(input.X)`.
    TimestampIso,
    /// `query_timestamp_epoch(input.X)`.
    TimestampEpoch,
}

/// One serialized input member of a query/ec2 request body, in model order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryMember {
    /// A single `Key=value` parameter.
    Scalar {
        key: String,
        field: String,
        text: ScalarText,
        optional: bool,
    },
    /// A flattened list of scalars (`Name.N`): awsQuery `@flattened` and every
    /// ec2 list.
    FlatList {
        name: String,
        field: String,
        optional: bool,
    },
    /// A wrapped list of scalars (`Name.member.N`): the awsQuery default.
    WrappedList {
        name: String,
        member: String,
        field: String,
        optional: bool,
    },
}

/// The query/ec2 plan for one operation: the `Action`, the model `Version`, and
/// the serialized input members in model order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryOp {
    pub action: String,
    pub version: String,
    pub input_shape: Option<String>,
    pub members: Vec<QueryMember>,
}

/// The on-the-wire key for a structure member under `flavor`:
///   * query — the member's `locationName`/`xmlName`, else its name;
///   * ec2   — its `queryName`, else the capitalized `locationName`/`xmlName`,
///     else its (unchanged) name.
fn serialized_name(flavor: QueryFlavor, member: &str, r: &crate::model::ShapeRef) -> String {
    match flavor {
        QueryFlavor::Query => r.xml_wire_name(member).to_string(),
        QueryFlavor::Ec2 => {
            if let Some(q) = &r.query_name {
                return q.clone();
            }
            match r.location_name.as_deref().or(r.xml_name.as_deref()) {
                Some(name) => capitalize(name),
                None => member.to_string(),
            }
        }
    }
}

/// Capitalize the first character (ASCII), leaving the rest untouched — the ec2
/// `locationName` rule (`dryRun` -> `DryRun`).
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// The scalar text encoding for a resolved scalar type, or `None` when the type
/// is not a serializable scalar (so the caller skips the operation).
fn scalar_text(ty: &ZapType) -> Option<ScalarText> {
    match ty {
        ZapType::Str | ZapType::Enum(_) => Some(ScalarText::Str),
        ZapType::Int => Some(ScalarText::Int),
        ZapType::Float => Some(ScalarText::Float),
        ZapType::Bool => Some(ScalarText::Bool),
        ZapType::Bytes => Some(ScalarText::Blob),
        ZapType::DateTime => Some(ScalarText::TimestampIso),
        _ => None,
    }
}

/// Whether a resolved type is a scalar the query codec can carry as a list
/// element (v0 lists hold strings / enums-as-strings only).
fn is_string_element(ty: &ZapType) -> bool {
    matches!(ty, ZapType::Str | ZapType::Enum(_))
}

/// Plan the query/ec2 serialization for `op`, or return a short reason it must
/// be skipped (a nested structure, a map, or a list of non-scalars — all codec
/// follow-ups). `flavor` selects the key convention and list flattening.
pub fn plan_query(model: &Model, op: &Operation, flavor: QueryFlavor) -> Result<QueryOp, String> {
    let version = model.metadata.api_version.clone();
    if version.is_empty() {
        return Err("model has no apiVersion for the query Version parameter".to_string());
    }

    let mut plan = QueryOp {
        action: op.name.clone(),
        version,
        input_shape: None,
        members: Vec::new(),
    };

    let input_ref = match op.input.as_ref() {
        Some(r) => r,
        None => return Ok(plan),
    };
    let input = model
        .shape(&input_ref.shape)
        .filter(|s| s.is_structure())
        .ok_or("input is not a structure shape")?;
    plan.input_shape = Some(escape_ident(&input_ref.shape).0);
    if input.members.is_empty() {
        return Ok(plan);
    }

    for (mn, r) in &input.members {
        let field = escape_ident(mn).0;
        let key = serialized_name(flavor, mn, r);
        let optional = !input.required.contains(mn);
        let ty = resolve(model, &r.shape);

        match &ty {
            ZapType::List(elem) => {
                if !is_string_element(elem) {
                    return Err(format!(
                        "member `{mn}` is a list of {} (only scalar lists in v0)",
                        elem.render()
                    ));
                }
                let shape = model.shape(&r.shape);
                let flattened = flavor == QueryFlavor::Ec2
                    || r.flattened
                    || shape.map(|s| s.flattened).unwrap_or(false);
                if flattened {
                    plan.members.push(QueryMember::FlatList {
                        name: key,
                        field,
                        optional,
                    });
                } else {
                    // The wrapped-list element segment: the list member's
                    // locationName/xmlName, else "member".
                    let member_seg = shape
                        .and_then(|s| s.member.as_ref())
                        .map(|m| m.xml_wire_name("member").to_string())
                        .unwrap_or_else(|| "member".to_string());
                    plan.members.push(QueryMember::WrappedList {
                        name: key,
                        member: member_seg,
                        field,
                        optional,
                    });
                }
            }
            ZapType::Dict(..) => {
                return Err(format!(
                    "member `{mn}` is a map (query maps are a v0 follow-up)"
                ));
            }
            ZapType::Struct(_) => {
                return Err(format!(
                    "member `{mn}` is a nested structure (query nesting is a v0 follow-up)"
                ));
            }
            scalar => {
                let text = scalar_text(scalar).ok_or_else(|| {
                    format!("member `{mn}` has unsupported type {}", scalar.render())
                })?;
                plan.members.push(QueryMember::Scalar {
                    key,
                    field,
                    text,
                    optional,
                });
            }
        }
    }

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = r#"{
      "metadata":{"protocol":"query","apiVersion":"2011-06-15","endpointPrefix":"svc"},
      "operations":{
        "DoThing":{"name":"DoThing","input":{"shape":"DoThingRequest"}},
        "BadMap":{"name":"BadMap","input":{"shape":"BadMapRequest"}}
      },
      "shapes":{
        "S":{"type":"string"},
        "I":{"type":"integer"},
        "B":{"type":"boolean"},
        "FlatList":{"type":"list","member":{"shape":"S"},"flattened":true},
        "WrapList":{"type":"list","member":{"shape":"S"}},
        "StrMap":{"type":"map","key":{"shape":"S"},"value":{"shape":"S"}},
        "DoThingRequest":{"type":"structure","required":["Name"],"members":{
          "Name":{"shape":"S"},
          "Count":{"shape":"I"},
          "Flag":{"shape":"B"},
          "Flat":{"shape":"FlatList"},
          "Wrapped":{"shape":"WrapList"}}},
        "BadMapRequest":{"type":"structure","members":{"M":{"shape":"StrMap"}}}
      }}"#;

    fn plan(flavor: QueryFlavor) -> QueryOp {
        let m = Model::from_json_str(M).unwrap();
        plan_query(&m, &m.operations["DoThing"], flavor).unwrap()
    }

    #[test]
    fn awsquery_keys_and_lists() {
        let p = plan(QueryFlavor::Query);
        assert_eq!(p.action, "DoThing");
        assert_eq!(p.version, "2011-06-15");
        // Scalar, int, bool, a flattened list and a wrapped list, in model order.
        assert_eq!(
            p.members,
            vec![
                QueryMember::Scalar {
                    key: "Name".into(),
                    field: "Name".into(),
                    text: ScalarText::Str,
                    optional: false
                },
                QueryMember::Scalar {
                    key: "Count".into(),
                    field: "Count".into(),
                    text: ScalarText::Int,
                    optional: true
                },
                QueryMember::Scalar {
                    key: "Flag".into(),
                    field: "Flag".into(),
                    text: ScalarText::Bool,
                    optional: true
                },
                QueryMember::FlatList {
                    name: "Flat".into(),
                    field: "Flat".into(),
                    optional: true
                },
                QueryMember::WrappedList {
                    name: "Wrapped".into(),
                    member: "member".into(),
                    field: "Wrapped".into(),
                    optional: true
                },
            ]
        );
    }

    #[test]
    fn ec2_flavor_capitalizes_and_flattens() {
        let m = Model::from_json_str(
            r#"{"metadata":{"protocol":"ec2","apiVersion":"2014-09-01","endpointPrefix":"ec2"},
              "operations":{"Op":{"name":"Op","input":{"shape":"Req"}}},
              "shapes":{
                "S":{"type":"string"},
                "Bool":{"type":"boolean"},
                "L":{"type":"list","member":{"shape":"S","locationName":"Item"}},
                "Req":{"type":"structure","required":["Ids"],"members":{
                  "DryRun":{"shape":"Bool","locationName":"dryRun"},
                  "Ids":{"shape":"L","locationName":"InstanceId"}}}}}"#,
        )
        .unwrap();
        let p = plan_query(&m, &m.operations["Op"], QueryFlavor::Ec2).unwrap();
        // dryRun -> DryRun (capitalized); the list is flattened to InstanceId.N
        // using the structure member's capitalized locationName.
        assert_eq!(
            p.members,
            vec![
                QueryMember::Scalar {
                    key: "DryRun".into(),
                    field: "DryRun".into(),
                    text: ScalarText::Bool,
                    optional: true
                },
                QueryMember::FlatList {
                    name: "InstanceId".into(),
                    field: "Ids".into(),
                    optional: false
                },
            ]
        );
    }

    #[test]
    fn maps_and_nesting_are_skipped() {
        let m = Model::from_json_str(M).unwrap();
        let err = plan_query(&m, &m.operations["BadMap"], QueryFlavor::Query).unwrap_err();
        assert!(err.contains("map"), "{err}");
    }
}
