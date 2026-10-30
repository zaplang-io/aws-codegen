//! Explicit JSON body serialization for awsJson / rest-json (zaplang-io/zap#424).
//!
//! `@derive(Json)` serializes scalars, `str`, `bytes` (base64), `DateTime`
//! (epoch/iso8601), open enums and nested derivable structs — but **not**
//! `list` / `dict` members (the derive collection follow-up is not in the
//! toolchain). So the #364 rollout skipped every awsJson input / rest-json
//! document body that carried a nested structure, a map, or a list of
//! structures — ~4,935 operations, the single biggest coverage gap.
//!
//! This module closes it by emitting an **explicit** compact-JSON serializer per
//! body shape: a free `def <shape>_to_json(<Shape> v) -> str` that builds the
//! object string member-by-member in model (declaration) order, recursing for
//! nested structures, lists and maps. It produces the same bytes `@derive(Json)`
//! would for the parts derive can already do (declaration-order object,
//! `zap_json_escape` strings via `json.dumps`, `str(...)` numbers, epoch/iso8601
//! timestamps, base64 blobs) and extends the same shape to collections. A body
//! that is *fully* derivable is left on the `input.to_json()` path untouched (so
//! existing services regenerate byte-identically); only the previously-skipped
//! shapes gain an explicit serializer.
//!
//! Map key order: Zap `dict` iteration is hash order, so map keys are emitted
//! **sorted** for a deterministic body. AWS JSON maps are order-insensitive, so
//! this round-trips; it is the one intentional deviation from botocore's
//! input-order maps, and it keeps the byte-diff goldens reproducible.

use crate::model::{Model, Shape, ShapeRef};
use crate::naming::snake_case;
use crate::types::{resolve, ZapType};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};

const IND: &str = "    ";

/// How one value position is encoded to JSON text by the emitted serializer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonEnc {
    /// A `str` — escaped + quoted via the per-file `_json_str` helper.
    Str,
    /// An open enum carried as its type — serialized through its derived
    /// `.to_json()` (the quoted wire string), same as a derivable field.
    EnumVal,
    /// An integer / float — `str(x)`, matching derive + the query/xml emitters.
    Num,
    /// A bool — `json.dumps(JsonValue.Bool(x))` -> `true` / `false`.
    Bool,
    /// A blob — base64 string (standard alphabet, padded), then quoted.
    Blob,
    /// A timestamp as a JSON number of Unix epoch seconds (the JSON default).
    TsEpoch,
    /// A timestamp as an ISO-8601 JSON string (`@json(timestamp="iso8601")`).
    TsIso,
    /// A nested structure, by raw (model) shape name. `derivable` is true when
    /// the struct is `@derive(Json)` (serialized via its `.to_json()`); false
    /// when it needs its own explicit serializer.
    Struct { name: String, derivable: bool },
    /// A list — `[...]` over the element encoding.
    List(Box<JsonEnc>),
    /// A string-keyed map — `{...}` with sorted keys over the value encoding.
    Map(Box<JsonEnc>),
}

/// Resolve the timestamp format for a member reference to its JSON encoding:
/// `iso8601` -> an ISO string, everything else -> epoch seconds (the JSON
/// default; `rfc822` is not a JSON body form, so it degrades to epoch, matching
/// the existing derive-struct emission).
fn ts_enc(model: &Model, r: &ShapeRef) -> JsonEnc {
    let fmt = r.timestamp_format.as_deref().or_else(|| {
        model
            .shape(&r.shape)
            .and_then(|s| s.timestamp_format.as_deref())
    });
    match fmt {
        Some("iso8601") => JsonEnc::TsIso,
        _ => JsonEnc::TsEpoch,
    }
}

/// Plan the JSON encoding of a member reference, or `None` when the generator
/// cannot serialize it byte-faithfully yet (a map with a non-string key). The
/// `serializable` verdict decides whether a nested structure rides its own
/// `@derive(Json).to_json()` or needs an explicit serializer.
pub fn plan_enc(
    model: &Model,
    r: &ShapeRef,
    derivable: &HashMap<String, bool>,
    serializable: &HashMap<String, bool>,
) -> Option<JsonEnc> {
    match resolve(model, &r.shape) {
        ZapType::Str => Some(JsonEnc::Str),
        ZapType::Enum(_) => Some(JsonEnc::EnumVal),
        ZapType::Int | ZapType::Float => Some(JsonEnc::Num),
        ZapType::Bool => Some(JsonEnc::Bool),
        ZapType::Bytes => Some(JsonEnc::Blob),
        ZapType::DateTime => Some(ts_enc(model, r)),
        ZapType::Struct(_) => {
            // Look the verdicts up by the raw (model) shape name the ref points
            // at, which is also how `derivable` / `serializable` are keyed.
            let raw = r.shape.clone();
            if !*serializable.get(&raw).unwrap_or(&false) {
                return None;
            }
            Some(JsonEnc::Struct {
                derivable: *derivable.get(&raw).unwrap_or(&false),
                name: raw,
            })
        }
        ZapType::List(_) => {
            let elem = model.shape(&r.shape).and_then(|s| s.member.clone())?;
            let inner = plan_enc(model, &elem, derivable, serializable)?;
            Some(JsonEnc::List(Box::new(inner)))
        }
        ZapType::Dict(k, _) => {
            // AWS JSON map keys are always strings (enum-keyed maps are a rare
            // follow-up); a non-string key is not serializable here.
            if *k != ZapType::Str {
                return None;
            }
            let val = model.shape(&r.shape).and_then(|s| s.value.clone())?;
            let inner = plan_enc(model, &val, derivable, serializable)?;
            Some(JsonEnc::Map(Box::new(inner)))
        }
    }
}

/// Compute, for every structure shape, whether the explicit JSON emitter can
/// serialize it: every member must plan an encoding. Collections of
/// serializable elements are fine (unlike the derive verdict), so this is a
/// superset of `types::compute_derivable`. Computed to a fixpoint so recursive
/// shapes (a struct holding a list of itself) settle correctly.
pub fn compute_json_serializable(
    model: &Model,
    derivable: &HashMap<String, bool>,
) -> HashMap<String, bool> {
    let structs: Vec<&String> = model
        .shapes
        .iter()
        .filter(|(_, s)| s.is_structure())
        .map(|(n, _)| n)
        .collect();
    let mut verdict: HashMap<String, bool> = structs.iter().map(|n| ((*n).clone(), true)).collect();

    loop {
        let mut changed = false;
        for name in &structs {
            if !verdict[*name] {
                continue;
            }
            let shape = model.shape(name).unwrap();
            let ok = shape
                .members
                .values()
                .all(|r| plan_enc(model, r, derivable, &verdict).is_some());
            if !ok {
                verdict.insert((*name).clone(), false);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    verdict
}

/// The emitter: builds the explicit `_to_json` serializers for a set of body
/// shapes and the per-file JSON helpers they share. Carries the service's
/// function-name prefix (for the helpers) and the model-wide verdicts, and
/// records which runtime imports (`base64`, `datetime`) the emitted code needs.
pub struct JsonSer<'a> {
    model: &'a Model,
    prefix: &'a str,
    derivable: &'a HashMap<String, bool>,
    serializable: &'a HashMap<String, bool>,
    /// shape name -> emitted serializer function name (collision-free).
    fn_names: HashMap<String, String>,
    needs_base64: Cell<bool>,
    needs_datetime: Cell<bool>,
    needs_iso: Cell<bool>,
}

impl<'a> JsonSer<'a> {
    pub fn new(
        model: &'a Model,
        prefix: &'a str,
        derivable: &'a HashMap<String, bool>,
        serializable: &'a HashMap<String, bool>,
    ) -> Self {
        JsonSer {
            model,
            prefix,
            derivable,
            serializable,
            fn_names: HashMap::new(),
            needs_base64: Cell::new(false),
            needs_datetime: Cell::new(false),
            needs_iso: Cell::new(false),
        }
    }

    pub fn needs_base64(&self) -> bool {
        self.needs_base64.get()
    }
    pub fn needs_datetime(&self) -> bool {
        self.needs_datetime.get()
    }
    pub fn needs_iso(&self) -> bool {
        self.needs_iso.get()
    }

    /// Whether `shape_name` is serialized by an explicit emitted function (it is
    /// serializable but not derivable); derivable shapes ride `.to_json()`.
    pub fn needs_explicit(&self, shape_name: &str) -> bool {
        *self.serializable.get(shape_name).unwrap_or(&false)
            && !*self.derivable.get(shape_name).unwrap_or(&false)
    }

    /// The serializer expression for a whole body shape `v` of type `shape_name`
    /// (the client method's `auto body = <this>`): `v.to_json()` for a derivable
    /// shape, else the explicit `<shape>_to_json(v)`.
    pub fn body_expr(&self, shape_name: &str, v: &str) -> String {
        if self.needs_explicit(shape_name) {
            format!("{}({v})", self.fn_name(shape_name))
        } else {
            format!("{v}.to_json()")
        }
    }

    /// Collect, from the given request-body root shapes, every structure that
    /// needs an explicit serializer (serializable-but-not-derivable, reachable
    /// through struct / list / map members), and assign each a collision-free
    /// function name. Call once before `emit_serializers`.
    pub fn plan_roots(&mut self, roots: &[String]) {
        let mut seen: HashSet<String> = HashSet::new();
        let mut order: Vec<String> = Vec::new();
        let mut stack: Vec<String> = roots.to_vec();
        while let Some(name) = stack.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            let shape = match self.model.shape(&name) {
                Some(s) if s.is_structure() => s,
                _ => continue,
            };
            if self.needs_explicit(&name) {
                order.push(name.clone());
            }
            for r in shape.members.values() {
                for dep in reachable_struct_names(self.model, r) {
                    if !seen.contains(&dep) {
                        stack.push(dep);
                    }
                }
            }
        }
        // Deterministic emission order + collision-free names.
        order.sort();
        order.dedup();
        let mut used: Vec<String> = Vec::new();
        for name in &order {
            let base = format!("{}_to_json", snake_case(name));
            let unique = unique_name(&base, &used);
            used.push(unique.clone());
            self.fn_names.insert(name.clone(), unique);
        }
    }

    /// The emitted serializer function name for `shape_name` (must have been
    /// planned via `plan_roots`).
    fn fn_name(&self, shape_name: &str) -> String {
        self.fn_names
            .get(shape_name)
            .cloned()
            .unwrap_or_else(|| format!("{}_to_json", snake_case(shape_name)))
    }

    /// Emit every planned explicit serializer, in deterministic order.
    pub fn emit_serializers(&self) -> String {
        let mut names: Vec<&String> = self.fn_names.keys().collect();
        names.sort();
        let mut out = String::new();
        for name in names {
            let shape = self.model.shape(name).unwrap();
            out.push_str(&self.emit_struct_fn(name, shape));
            out.push('\n');
        }
        out
    }

    fn emit_struct_fn(&self, name: &str, shape: &Shape) -> String {
        use crate::naming::escape_ident;
        let ty = escape_ident(name).0;
        let func = self.fn_name(name);
        let mut out = String::new();
        out.push_str(&format!(
            "# Serialize {name} to a compact JSON object (declaration order).\n"
        ));
        out.push_str(&format!("def {func}({ty} v) -> str:\n"));
        if shape.members.is_empty() {
            out.push_str(&format!("{IND}return \"{{}}\"\n"));
            return out;
        }
        out.push_str(&format!("{IND}list[str] parts = []\n"));
        let mut ctr: u32 = 0;
        for (mn, r) in &shape.members {
            let enc = match plan_enc(self.model, r, self.derivable, self.serializable) {
                Some(e) => e,
                // Guarded by `serializable`; unreachable, but stay safe.
                None => continue,
            };
            let wire = r.wire_name(mn);
            let field = escape_ident(mn).0;
            let optional = !shape.required.contains(mn);
            self.append_member(
                &mut out, IND, "parts", "v", &field, wire, optional, &enc, &mut ctr,
            );
        }
        out.push_str(&format!("{IND}return {}_json_obj(parts)\n", self.prefix));
        out
    }

    /// Emit the statements that append one member's `"wire":value` fragment to
    /// `parts_var` (at `indent`). `base.field` is the member access; an optional
    /// member is guarded by `is_some()` and unwrapped to a fresh temp first.
    /// Shared by the struct serializers and the rest-json inline document body.
    #[allow(clippy::too_many_arguments)]
    pub fn append_member(
        &self,
        out: &mut String,
        indent: &str,
        parts_var: &str,
        base: &str,
        field: &str,
        wire: &str,
        optional: bool,
        enc: &JsonEnc,
        ctr: &mut u32,
    ) {
        if optional {
            out.push_str(&format!("{indent}if {base}.{field}.is_some():\n"));
            let bind = format!("u{ctr}");
            *ctr += 1;
            let inner = format!("{indent}{IND}");
            out.push_str(&format!("{inner}auto {bind} = {base}.{field}.unwrap()\n"));
            let expr = self.emit_value(enc, &bind, out, &inner, ctr);
            out.push_str(&format!(
                "{inner}{parts_var}.append(\"\\\"{wire}\\\":\" + {expr})\n"
            ));
        } else {
            let access = format!("{base}.{field}");
            let expr = self.emit_value(enc, &access, out, indent, ctr);
            out.push_str(&format!(
                "{indent}{parts_var}.append(\"\\\"{wire}\\\":\" + {expr})\n"
            ));
        }
    }

    /// The per-file `_json_obj` helper name (for building an inline object).
    pub fn obj_helper(&self) -> String {
        format!("{}_json_obj", self.prefix)
    }

    /// Emit any statements needed to serialize `access` under `enc` into `out`
    /// (at `indent`), and return the Zap expression for the resulting JSON text.
    /// `ctr` hands out collision-free temporary names.
    fn emit_value(
        &self,
        enc: &JsonEnc,
        access: &str,
        out: &mut String,
        indent: &str,
        ctr: &mut u32,
    ) -> String {
        let p = self.prefix;
        match enc {
            JsonEnc::Str => format!("{p}_json_str({access})"),
            JsonEnc::EnumVal => format!("{access}.to_json()"),
            JsonEnc::Num => format!("str({access})"),
            JsonEnc::Bool => format!("json.dumps(JsonValue.Bool({access}))"),
            JsonEnc::Blob => {
                self.needs_base64.set(true);
                format!("{p}_json_str(base64.encode({access}))")
            }
            JsonEnc::TsEpoch => {
                self.needs_datetime.set(true);
                format!("str(datetime.to_timestamp({access}))")
            }
            JsonEnc::TsIso => {
                self.needs_datetime.set(true);
                self.needs_iso.set(true);
                format!("{p}_json_ts_iso({access})")
            }
            JsonEnc::Struct { name, derivable } => {
                if *derivable {
                    format!("{access}.to_json()")
                } else {
                    format!("{}({access})", self.fn_name(name))
                }
            }
            JsonEnc::List(elem) => {
                let n = *ctr;
                *ctr += 1;
                let ev = format!("e{n}");
                let xv = format!("x{n}");
                out.push_str(&format!("{indent}list[str] {ev} = []\n"));
                out.push_str(&format!("{indent}for {xv} in {access}:\n"));
                let inner = format!("{indent}{IND}");
                let elem_expr = self.emit_value(elem, &xv, out, &inner, ctr);
                out.push_str(&format!("{inner}{ev}.append({elem_expr})\n"));
                format!("{p}_json_arr({ev})")
            }
            JsonEnc::Map(val) => {
                let n = *ctr;
                *ctr += 1;
                let mv = format!("m{n}");
                let kv = format!("k{n}");
                out.push_str(&format!("{indent}list[str] {mv} = []\n"));
                out.push_str(&format!("{indent}for {kv} in sorted({access}.keys()):\n"));
                let inner = format!("{indent}{IND}");
                let val_access = format!("{access}[{kv}]");
                let val_expr = self.emit_value(val, &val_access, out, &inner, ctr);
                out.push_str(&format!(
                    "{inner}{mv}.append({p}_json_str({kv}) + \":\" + {val_expr})\n"
                ));
                format!("{p}_json_obj({mv})")
            }
        }
    }
}

/// The struct shape names directly reachable through a member reference
/// (through list element / map value nesting), used to walk the body graph.
pub fn reachable_struct_names(model: &Model, r: &ShapeRef) -> Vec<String> {
    match resolve(model, &r.shape) {
        ZapType::Struct(n) => vec![n],
        ZapType::List(_) => model
            .shape(&r.shape)
            .and_then(|s| s.member.clone())
            .map(|m| reachable_struct_names(model, &m))
            .unwrap_or_default(),
        ZapType::Dict(..) => model
            .shape(&r.shape)
            .and_then(|s| s.value.clone())
            .map(|v| reachable_struct_names(model, &v))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Make `base` unique against `used` (append `_2`, `_3`, …).
fn unique_name(base: &str, used: &[String]) -> String {
    if !used.iter().any(|u| u == base) {
        return base.to_string();
    }
    let mut n = 2;
    loop {
        let cand = format!("{base}_{n}");
        if !used.contains(&cand) {
            return cand;
        }
        n += 1;
    }
}
