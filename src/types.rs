//! AWS shape -> Zap type resolution, and the derivability analysis that decides
//! which structs can carry `@derive(Json)`.
//!
//! `@derive(Json)` (zaplang-io/zap#346) handles scalars, `str`, `bytes` (base64
//! blob), `DateTime` (timestamp), nested derivable structs and `@json(open)`
//! string enums. It does **not** handle `list`/`dict` fields yet (collections in
//! derive are a #346 follow-up), so any structure that transitively contains a
//! collection member cannot be derived and is emitted as a plain struct.

use crate::model::Model;
use crate::naming::escape_ident;
use std::collections::{HashMap, HashSet};

/// A resolved Zap type for a shape reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZapType {
    Str,
    Int,
    Float,
    Bool,
    Bytes,
    DateTime,
    /// An `@json(open)` string enum, by generated type name.
    Enum(String),
    /// A nested structure, by generated type name.
    Struct(String),
    List(Box<ZapType>),
    Dict(Box<ZapType>, Box<ZapType>),
}

impl ZapType {
    /// Render the type as Zap source.
    pub fn render(&self) -> String {
        match self {
            ZapType::Str => "str".to_string(),
            ZapType::Int => "int64".to_string(),
            ZapType::Float => "float64".to_string(),
            ZapType::Bool => "bool".to_string(),
            ZapType::Bytes => "bytes".to_string(),
            ZapType::DateTime => "DateTime".to_string(),
            ZapType::Enum(n) => n.clone(),
            ZapType::Struct(n) => n.clone(),
            ZapType::List(e) => format!("list[{}]", e.render()),
            ZapType::Dict(k, v) => format!("dict[{}, {}]", k.render(), v.render()),
        }
    }

    /// Whether this type is a collection (list/map) — the derive gap.
    pub fn is_collection(&self) -> bool {
        matches!(self, ZapType::List(_) | ZapType::Dict(..))
    }
}

/// Resolve a shape name to its Zap type. Unknown shapes fall back to `str`.
pub fn resolve(model: &Model, shape_name: &str) -> ZapType {
    let shape = match model.shape(shape_name) {
        Some(s) => s,
        None => return ZapType::Str,
    };
    match shape.kind.as_str() {
        "string" => {
            if shape.is_enum() {
                ZapType::Enum(escape_ident(shape_name).0)
            } else {
                ZapType::Str
            }
        }
        "integer" | "long" => ZapType::Int,
        "float" | "double" => ZapType::Float,
        "boolean" => ZapType::Bool,
        "blob" => ZapType::Bytes,
        "timestamp" => ZapType::DateTime,
        "structure" => ZapType::Struct(escape_ident(shape_name).0),
        "list" => {
            let elem = shape
                .member
                .as_ref()
                .map(|r| resolve(model, &r.shape))
                .unwrap_or(ZapType::Str);
            ZapType::List(Box::new(elem))
        }
        "map" => {
            let key = shape
                .key
                .as_ref()
                .map(|r| resolve(model, &r.shape))
                .unwrap_or(ZapType::Str);
            let val = shape
                .value
                .as_ref()
                .map(|r| resolve(model, &r.shape))
                .unwrap_or(ZapType::Str);
            ZapType::Dict(Box::new(key), Box::new(val))
        }
        _ => ZapType::Str,
    }
}

/// Compute, for every structure shape, whether it is JSON-derivable.
///
/// A structure is derivable iff every member's underlying type is derivable:
/// scalars/str/bytes/DateTime/open-enum are always derivable; a nested struct
/// is derivable iff *it* is; any list/dict member makes the struct non-derivable.
/// Computed to a fixpoint so cycles (e.g. `AttributeValue` -> `list` of itself)
/// settle to non-derivable.
pub fn compute_derivable(model: &Model) -> HashMap<String, bool> {
    let structs: Vec<&String> = model
        .shapes
        .iter()
        .filter(|(_, s)| s.is_structure())
        .map(|(n, _)| n)
        .collect();

    let struct_set: HashSet<&str> = structs.iter().map(|s| s.as_str()).collect();
    // Start optimistic, then knock out anything with a non-derivable member.
    let mut derivable: HashMap<String, bool> =
        structs.iter().map(|n| ((*n).clone(), true)).collect();

    loop {
        let mut changed = false;
        for name in &structs {
            if !derivable[*name] {
                continue;
            }
            let shape = model.shape(name).unwrap();
            let ok = shape
                .members
                .values()
                .all(|r| member_type_derivable(&resolve(model, &r.shape), &struct_set, &derivable));
            if !ok {
                derivable.insert((*name).clone(), false);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    derivable
}

/// Whether a member's resolved type is derivable given the current struct verdicts.
fn member_type_derivable(
    ty: &ZapType,
    struct_set: &HashSet<&str>,
    derivable: &HashMap<String, bool>,
) -> bool {
    match ty {
        ZapType::List(_) | ZapType::Dict(..) => false,
        ZapType::Struct(n) => {
            // A struct type we model: derivable iff its verdict says so. A name
            // we did not resolve to a known struct is treated conservatively.
            if struct_set.contains(n.as_str()) {
                *derivable.get(n).unwrap_or(&false)
            } else {
                derivable.get(n).copied().unwrap_or(false)
            }
        }
        // scalars, str, bytes, DateTime, open enum.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(json: &str) -> Model {
        Model::from_json_str(json).unwrap()
    }

    #[test]
    fn resolves_scalars_and_collections() {
        let m = model(
            r#"{"metadata":{},"operations":{},"shapes":{
              "S":{"type":"string"},
              "N":{"type":"long"},
              "L":{"type":"list","member":{"shape":"S"}},
              "M":{"type":"map","key":{"shape":"S"},"value":{"shape":"N"}},
              "E":{"type":"string","enum":["A","B"]}
            }}"#,
        );
        assert_eq!(resolve(&m, "S"), ZapType::Str);
        assert_eq!(resolve(&m, "N"), ZapType::Int);
        assert_eq!(resolve(&m, "L"), ZapType::List(Box::new(ZapType::Str)));
        assert_eq!(resolve(&m, "E"), ZapType::Enum("E".to_string()));
        assert_eq!(resolve(&m, "M").render(), "dict[str, int64]");
    }

    #[test]
    fn derivability_fixpoint() {
        let m = model(
            r#"{"metadata":{},"operations":{},"shapes":{
              "Flat":{"type":"structure","members":{"a":{"shape":"S"}}},
              "HasList":{"type":"structure","members":{"xs":{"shape":"L"}}},
              "Nested":{"type":"structure","members":{"f":{"shape":"Flat"}}},
              "NestedBad":{"type":"structure","members":{"f":{"shape":"HasList"}}},
              "S":{"type":"string"},
              "L":{"type":"list","member":{"shape":"S"}}
            }}"#,
        );
        let d = compute_derivable(&m);
        assert!(d["Flat"]);
        assert!(!d["HasList"]);
        assert!(d["Nested"]);
        assert!(!d["NestedBad"]);
    }
}
