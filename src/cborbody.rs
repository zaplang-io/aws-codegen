//! Explicit CBOR body serialization for smithy-rpc-v2-cbor (zaplang-io/zap#428,
//! part 2 — the generator/emitter half).
//!
//! smithy-rpc-v2-cbor is the RPC protocol spoken by the 25 services excluded from
//! the #364 broad rollout (CloudWatch — moved query→cbor upstream — Translate,
//! GameLift, Keyspaces, …). Like awsJson it binds nothing to the URI/query/header:
//! the whole operation input is serialized as one CBOR data item in the POST body.
//! Unlike awsJson there is no `@derive(Cbor)`, so every body shape is serialized by
//! an **explicit** emitted serializer — a free
//! `def <shape>_to_cbor(<Shape> v) -> cbor.CborValue` that builds the value tree
//! member-by-member in model (declaration) order and hands it to the aws_core
//! `cbor` codec (`cbor.cbor_encode`), which owns the canonical CBOR wire format
//! (the byte-diff oracle; aws #428 part 1). The generator reuses that codec and
//! never reimplements the encoding.
//!
//! Fidelity (verified against botocore's `RpcV2CBORSerializer`/`CBORSerializer`):
//!   * a structure is a CBOR map keyed by the (text) member wire name in MODEL
//!     order; botocore omits only absent (`None`) members (`{k: v for … if v is
//!     not None}`), never present-but-falsy ones, so required members are always
//!     emitted and optional members are emitted iff `is_some()`;
//!   * the AWS `float` shape is a 32-bit single (major 7, ai 26) and `double` is a
//!     64-bit double (ai 27) — the two are distinguished from the raw shape kind,
//!     since `types::resolve` collapses both to `ZapType::Float`;
//!   * a timestamp is CBOR tag 1 over integer Unix epoch-seconds (rpc-v2-cbor is
//!     always `unixtimestamp`, regardless of the model's `timestampFormat`);
//!   * a blob is raw bytes (no base64, unlike the JSON body).
//!
//! Map key order: Zap `dict` iteration is hash order, so modeled-map keys are
//! emitted **sorted** for a deterministic body — the same intentional deviation
//! `jsonbody` makes. CBOR maps are order-insensitive for AWS services, so this
//! round-trips; it never affects a *structure* (those keep model order).

use crate::model::{Model, Shape, ShapeRef};
use crate::naming::snake_case;
use crate::types::{resolve, ZapType};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};

const IND: &str = "    ";

/// How one value position is encoded to a `cbor.CborValue` by the emitted
/// serializer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborEnc {
    /// A `str` (or an open enum, carried as its plain wire `str` in the carrier
    /// struct) — `cbor.cbor_text`.
    Text,
    /// An integer / long — `cbor.cbor_int`.
    Int,
    /// The AWS `double` shape — `cbor.cbor_double` (64-bit, ai 27).
    Double,
    /// The AWS `float` shape — `cbor.cbor_single` (32-bit, ai 26).
    Single,
    /// A bool — `cbor.cbor_bool`.
    Bool,
    /// A blob — `cbor.cbor_blob` over the raw `bytes` (no base64).
    Blob,
    /// A timestamp — `cbor.cbor_timestamp(datetime.to_timestamp(x))` (tag 1 epoch).
    Timestamp,
    /// A nested structure, by raw (model) shape name — serialized by its own
    /// `<shape>_to_cbor`.
    Struct { name: String },
    /// A list — `cbor.cbor_list` over the element encoding.
    List(Box<CborEnc>),
    /// A text-keyed map — `cbor.cbor_map` with sorted keys over the value
    /// encoding.
    Map(Box<CborEnc>),
}

/// Plan the CBOR encoding of a member reference, or `None` when the generator
/// cannot serialize it byte-faithfully yet (a map with a non-text key). The
/// `serializable` verdict gates a nested structure (every reachable struct gets
/// its own serializer).
pub fn plan_cbor_enc(
    model: &Model,
    r: &ShapeRef,
    serializable: &HashMap<String, bool>,
) -> Option<CborEnc> {
    match resolve(model, &r.shape) {
        // An open enum is carried as its plain wire `str` in the carrier struct
        // (`render_member_type`), so it encodes like a text string.
        ZapType::Str | ZapType::Enum(_) => Some(CborEnc::Text),
        ZapType::Int => Some(CborEnc::Int),
        ZapType::Float => {
            // `resolve` collapses `float`/`double` to `Float`; the CBOR wire form
            // differs (single vs double), so pick from the raw shape kind.
            let kind = model
                .shape(&r.shape)
                .map(|s| s.kind.as_str())
                .unwrap_or("double");
            if kind == "float" {
                Some(CborEnc::Single)
            } else {
                Some(CborEnc::Double)
            }
        }
        ZapType::Bool => Some(CborEnc::Bool),
        ZapType::Bytes => Some(CborEnc::Blob),
        ZapType::DateTime => Some(CborEnc::Timestamp),
        ZapType::Struct(_) => {
            let raw = r.shape.clone();
            if !*serializable.get(&raw).unwrap_or(&false) {
                return None;
            }
            Some(CborEnc::Struct { name: raw })
        }
        ZapType::List(_) => {
            let elem = model.shape(&r.shape).and_then(|s| s.member.clone())?;
            let inner = plan_cbor_enc(model, &elem, serializable)?;
            Some(CborEnc::List(Box::new(inner)))
        }
        ZapType::Dict(k, _) => {
            // AWS map keys are strings (or string enums); both are carried as
            // `str` in the carrier and ship as CBOR text keys. A non-text key
            // (unusual) is not serializable here.
            if *k != ZapType::Str && !matches!(*k, ZapType::Enum(_)) {
                return None;
            }
            let val = model.shape(&r.shape).and_then(|s| s.value.clone())?;
            let inner = plan_cbor_enc(model, &val, serializable)?;
            Some(CborEnc::Map(Box::new(inner)))
        }
    }
}

/// Compute, for every structure shape, whether the CBOR emitter can serialize it:
/// every member must plan an encoding. Collections of serializable elements are
/// fine; the only blocker is a non-text-keyed map (transitively). Computed to a
/// fixpoint so recursive shapes settle correctly.
pub fn compute_cbor_serializable(model: &Model) -> HashMap<String, bool> {
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
                .all(|r| plan_cbor_enc(model, r, &verdict).is_some());
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

/// The emitter: builds the explicit `_to_cbor` serializers for the set of body
/// shapes reachable from a service's operations, and records whether the emitted
/// code needs `import datetime` (for a timestamp member).
pub struct CborSer<'a> {
    model: &'a Model,
    serializable: &'a HashMap<String, bool>,
    /// shape name -> emitted serializer function name (collision-free).
    fn_names: HashMap<String, String>,
    needs_datetime: Cell<bool>,
}

impl<'a> CborSer<'a> {
    pub fn new(model: &'a Model, serializable: &'a HashMap<String, bool>) -> Self {
        CborSer {
            model,
            serializable,
            fn_names: HashMap::new(),
            needs_datetime: Cell::new(false),
        }
    }

    pub fn needs_datetime(&self) -> bool {
        self.needs_datetime.get()
    }

    fn is_serializable(&self, name: &str) -> bool {
        *self.serializable.get(name).unwrap_or(&false)
    }

    /// The serializer function name for `shape_name` (must have been planned).
    fn fn_name(&self, shape_name: &str) -> String {
        self.fn_names
            .get(shape_name)
            .cloned()
            .unwrap_or_else(|| format!("{}_to_cbor", snake_case(shape_name)))
    }

    /// The body expression for the client method: the CBOR `bytes` for a whole
    /// input shape `v` of type `shape_name` — `cbor.cbor_encode(<shape>_to_cbor(v))`.
    pub fn body_expr(&self, shape_name: &str, v: &str) -> String {
        format!("cbor.cbor_encode({}({v}))", self.fn_name(shape_name))
    }

    /// Collect, from the given request-body root shapes, every structure that
    /// needs a serializer (serializable, reachable through struct / list / map
    /// members — unlike JSON there is no derive fast path, so *every* reachable
    /// serializable struct gets one), and assign each a collision-free function
    /// name. Call once before `emit_serializers`.
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
            if self.is_serializable(&name) {
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
        order.sort();
        order.dedup();
        let mut used: Vec<String> = Vec::new();
        for name in &order {
            let base = format!("{}_to_cbor", snake_case(name));
            let unique = unique_name(&base, &used);
            used.push(unique.clone());
            self.fn_names.insert(name.clone(), unique);
        }
    }

    /// Emit every planned serializer, in deterministic (sorted) order.
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
            "# Serialize {name} to a CBOR map (member wire name -> value, model order).\n"
        ));
        out.push_str(&format!(
            "def {func}({ty} v) -> cbor.CborValue:\n{IND}list[str] keys = []\n{IND}list[cbor.CborValue] vals = []\n"
        ));
        let mut ctr: u32 = 0;
        for (mn, r) in &shape.members {
            let enc = match plan_cbor_enc(self.model, r, self.serializable) {
                Some(e) => e,
                // Guarded by `serializable`; unreachable, but stay safe.
                None => continue,
            };
            let wire = r.wire_name(mn);
            let field = escape_ident(mn).0;
            let optional = !shape.required.contains(mn);
            self.append_member(&mut out, IND, "v", &field, wire, optional, &enc, &mut ctr);
        }
        out.push_str(&format!("{IND}return cbor.cbor_map(keys, vals)\n"));
        out
    }

    /// Append the statements that push one member's wire name + encoded value onto
    /// the parallel `keys`/`vals` accumulators. A required member is emitted
    /// unconditionally; an optional member is guarded by `is_some()` and unwrapped
    /// to a fresh temp first (matching botocore's absent-member omission).
    #[allow(clippy::too_many_arguments)]
    fn append_member(
        &self,
        out: &mut String,
        indent: &str,
        base: &str,
        field: &str,
        wire: &str,
        optional: bool,
        enc: &CborEnc,
        ctr: &mut u32,
    ) {
        if optional {
            out.push_str(&format!("{indent}if {base}.{field}.is_some():\n"));
            let bind = format!("u{ctr}");
            *ctr += 1;
            let inner = format!("{indent}{IND}");
            out.push_str(&format!("{inner}auto {bind} = {base}.{field}.unwrap()\n"));
            let expr = self.emit_value(enc, &bind, out, &inner, ctr);
            out.push_str(&format!("{inner}keys.append(\"{wire}\")\n"));
            out.push_str(&format!("{inner}vals.append({expr})\n"));
        } else {
            let access = format!("{base}.{field}");
            let expr = self.emit_value(enc, &access, out, indent, ctr);
            out.push_str(&format!("{indent}keys.append(\"{wire}\")\n"));
            out.push_str(&format!("{indent}vals.append({expr})\n"));
        }
    }

    /// Emit any statements needed to build `access` under `enc` into `out` (at
    /// `indent`), and return the Zap expression for the resulting `cbor.CborValue`.
    fn emit_value(
        &self,
        enc: &CborEnc,
        access: &str,
        out: &mut String,
        indent: &str,
        ctr: &mut u32,
    ) -> String {
        match enc {
            CborEnc::Text => format!("cbor.cbor_text({access})"),
            CborEnc::Int => format!("cbor.cbor_int({access})"),
            CborEnc::Double => format!("cbor.cbor_double({access})"),
            CborEnc::Single => format!("cbor.cbor_single({access})"),
            CborEnc::Bool => format!("cbor.cbor_bool({access})"),
            CborEnc::Blob => format!("cbor.cbor_blob({access})"),
            CborEnc::Timestamp => {
                self.needs_datetime.set(true);
                format!("cbor.cbor_timestamp(datetime.to_timestamp({access}))")
            }
            CborEnc::Struct { name } => format!("{}({access})", self.fn_name(name)),
            CborEnc::List(elem) => {
                let n = *ctr;
                *ctr += 1;
                let ev = format!("e{n}");
                let xv = format!("x{n}");
                out.push_str(&format!("{indent}list[cbor.CborValue] {ev} = []\n"));
                out.push_str(&format!("{indent}for {xv} in {access}:\n"));
                let inner = format!("{indent}{IND}");
                let elem_expr = self.emit_value(elem, &xv, out, &inner, ctr);
                out.push_str(&format!("{inner}{ev}.append({elem_expr})\n"));
                format!("cbor.cbor_list({ev})")
            }
            CborEnc::Map(val) => {
                let n = *ctr;
                *ctr += 1;
                let kv = format!("mk{n}");
                let vv = format!("mv{n}");
                let keyv = format!("k{n}");
                out.push_str(&format!("{indent}list[str] {kv} = []\n"));
                out.push_str(&format!("{indent}list[cbor.CborValue] {vv} = []\n"));
                out.push_str(&format!("{indent}for {keyv} in sorted({access}.keys()):\n"));
                let inner = format!("{indent}{IND}");
                let val_access = format!("{access}[{keyv}]");
                let val_expr = self.emit_value(val, &val_access, out, &inner, ctr);
                out.push_str(&format!("{inner}{kv}.append({keyv})\n"));
                out.push_str(&format!("{inner}{vv}.append({val_expr})\n"));
                format!("cbor.cbor_map({kv}, {vv})")
            }
        }
    }
}

/// The struct shape names directly reachable through a member reference (through
/// list element / map value nesting), used to walk the body graph.
pub fn reachable_struct_names(model: &Model, r: &ShapeRef) -> Vec<String> {
    match resolve(model, &r.shape) {
        ZapType::Struct(_) => vec![r.shape.clone()],
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
