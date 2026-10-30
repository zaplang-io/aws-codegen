//! query + ec2 protocol serialization planning and emission.
//!
//! The `query` protocol (IAM, STS, SNS, SimpleDB, autoscaling, rds, …) and its
//! `ec2` variant POST the whole input as a flat `application/x-www-form-urlencoded`
//! body — no URI / query / header binding — with the operation chosen by an
//! `Action` parameter and the model pinned by a `Version` parameter. This module
//! serializes an operation's input into the form parameters the hand-written
//! `aws.query` codec (zaplang-io/aws#353) produces, mirroring botocore's
//! `QuerySerializer` / `EC2Serializer` (botocore 1.43.121).
//!
//! Each member maps to one dotted-key convention (the codec/botocore contract):
//!   * a scalar  -> `query_scalar(p, Key, text)`;
//!   * a string/enum list -> `query_flat_list` (`Name.N`) or `query_list`
//!     (`Name.member.N`) — the codec helpers (unchanged from #354);
//!   * a non-string-scalar / nested list -> a manual 1-based index loop building
//!     `Name[.member].N[.sub]` keys;
//!   * a `map[str, scalar]` -> `query_map` / `query_flat_map`
//!     (`Name.entry.N.key/value` or `Name.N.key/value`);
//!   * a `map[str, struct]` -> a manual loop + the nested serializer;
//!   * a nested structure -> a per-shape `<shape>_to_query(p, prefix, v)` free
//!     function (so recursion terminates on cyclic shapes and is shared across
//!     operations), keyed `prefix.Member`.
//!
//! The only difference between the two flavors is the member *key* and list
//! flattening: `query` uses `locationName`/`xmlName`; `ec2` uses `queryName` else
//! the capitalized `locationName`, and every ec2 list is flattened (`Name.N`).
//!
//! #426 lifts the #354 v0 (flat scalar + scalar-list only) to nested structures,
//! lists of structures, and maps. A member the generator still cannot serialize
//! byte-faithfully (a list/map of lists/maps, or a free-form `document`) makes
//! the whole operation *skipped* with a documented reason rather than emitting a
//! body that would not match the oracle. Map keys are emitted `sorted()` for a
//! deterministic body (AWS query maps are order-insensitive), matching #424.

use crate::model::{Model, Operation, ShapeRef};
use crate::naming::{escape_ident, snake_case};
use crate::types::{resolve, ZapType};
use std::collections::{HashMap, HashSet};

const IND: &str = "    ";

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

/// How one value position is serialized into the form parameter list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryEnc {
    /// A scalar carried through one of the codec's text helpers.
    Scalar(ScalarText),
    /// A list of strings/enums: the codec's `query_flat_list` (`Name.N`) or
    /// `query_list` (`Name.member.N`). `member_seg` is the wrapped member tag.
    /// Kept byte-identical to #354 (no botocore element-rename) so already-
    /// generated services regenerate unchanged.
    ScalarList { flattened: bool, member_seg: String },
    /// A list of non-string elements (a non-string scalar, a nested structure,
    /// …): a manual 1-based index loop. `seg` is the key segment appended to the
    /// parent prefix for each element (wrapped: `member_seg` under the member
    /// key; flattened: the element-renamed name).
    List {
        flattened: bool,
        /// The wrapped member segment (`member`/elem name), unused when flattened.
        member_seg: String,
        /// The flattened list's effective last segment (element locationName else
        /// the member key), used only when `flattened`.
        flat_name: String,
        elem: Box<QueryEnc>,
    },
    /// A `map[str, scalar]`: the codec's `query_map` / `query_flat_map`.
    ScalarMap {
        flattened: bool,
        key_name: String,
        value_name: String,
        value: ScalarText,
    },
    /// A `map[str, non-scalar]`: a manual loop, each entry keyed
    /// `Name.entry.N.key` / `.value` (wrapped) or `Name.N.key` / `.value` (flat).
    Map {
        flattened: bool,
        key_name: String,
        value_name: String,
        value: Box<QueryEnc>,
    },
    /// A nested structure, serialized by its `<shape>_to_query` free function.
    Struct(String),
}

/// One serialized top-level input member of a query/ec2 request body, in model
/// order. The on-the-wire key is a literal here (the top level has no prefix),
/// which keeps already-generated services' output byte-identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMember {
    pub key: String,
    pub field: String,
    pub optional: bool,
    pub enc: QueryEnc,
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
fn serialized_name(flavor: QueryFlavor, member: &str, r: &ShapeRef) -> String {
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

/// A key/value map-entry suffix name under `flavor`, falling back to `default`
/// ("key"/"value") when the shape carries no serialization name. botocore does
/// not capitalize the default for ec2 — only an explicit `locationName`.
fn suffix_name(flavor: QueryFlavor, r: &ShapeRef, default: &str) -> String {
    match flavor {
        QueryFlavor::Query => r
            .location_name
            .as_deref()
            .or(r.xml_name.as_deref())
            .unwrap_or(default)
            .to_string(),
        QueryFlavor::Ec2 => {
            if let Some(q) = &r.query_name {
                return q.clone();
            }
            match r.location_name.as_deref().or(r.xml_name.as_deref()) {
                Some(name) => capitalize(name),
                None => default.to_string(),
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
/// is not a serializable scalar.
fn scalar_text(
    ty: &ZapType,
    r: &ShapeRef,
    shape: Option<&crate::model::Shape>,
) -> Option<ScalarText> {
    match ty {
        ZapType::Str | ZapType::Enum(_) => Some(ScalarText::Str),
        ZapType::Int => Some(ScalarText::Int),
        ZapType::Float => Some(ScalarText::Float),
        ZapType::Bool => Some(ScalarText::Bool),
        ZapType::Bytes => Some(ScalarText::Blob),
        ZapType::DateTime => {
            let fmt = r
                .timestamp_format
                .as_deref()
                .or_else(|| shape.and_then(|s| s.timestamp_format.as_deref()));
            match fmt {
                Some("unixTimestamp") | Some("epoch-seconds") => Some(ScalarText::TimestampEpoch),
                _ => Some(ScalarText::TimestampIso),
            }
        }
        _ => None,
    }
}

/// Whether a resolved type is a string/enum (carried verbatim as a list element
/// by the codec's `query_flat_list` / `query_list`).
fn is_string_element(ty: &ZapType) -> bool {
    matches!(ty, ZapType::Str | ZapType::Enum(_))
}

/// Plan the serialization of a member reference, or `None` when the generator
/// cannot serialize it byte-faithfully yet (a list/map of lists/maps, or a
/// free-form document). `serializable` is the model-wide struct verdict.
pub fn plan_enc(
    model: &Model,
    r: &ShapeRef,
    flavor: QueryFlavor,
    serializable: &HashMap<String, bool>,
) -> Option<QueryEnc> {
    let ty = resolve(model, &r.shape);
    let shape = model.shape(&r.shape);
    match &ty {
        ZapType::Struct(_) => {
            if *serializable.get(&r.shape).unwrap_or(&false) {
                Some(QueryEnc::Struct(r.shape.clone()))
            } else {
                None
            }
        }
        ZapType::List(_) => {
            let elem_ref = shape.and_then(|s| s.member.clone())?;
            let elem_ty = resolve(model, &elem_ref.shape);
            let flattened = flavor == QueryFlavor::Ec2
                || r.flattened
                || shape.map(|s| s.flattened).unwrap_or(false);
            // The wrapped member segment: the list element's name, else "member".
            let member_seg = if flavor == QueryFlavor::Ec2 {
                "member".to_string()
            } else {
                elem_ref.xml_wire_name("member").to_string()
            };
            if is_string_element(&elem_ty) {
                // Preserve the #354 scalar-list emission byte-for-byte.
                return Some(QueryEnc::ScalarList {
                    flattened,
                    member_seg,
                });
            }
            let inner = plan_enc(model, &elem_ref, flavor, serializable)?;
            // A list of lists/maps is not representable with a single index loop.
            if matches!(
                inner,
                QueryEnc::ScalarList { .. }
                    | QueryEnc::List { .. }
                    | QueryEnc::ScalarMap { .. }
                    | QueryEnc::Map { .. }
            ) {
                return None;
            }
            // Flattened element-rename (botocore): the list element's
            // locationName replaces the member key segment. ec2 never renames.
            let flat_name = if flavor == QueryFlavor::Ec2 {
                String::new()
            } else {
                elem_ref
                    .location_name
                    .as_deref()
                    .or(elem_ref.xml_name.as_deref())
                    .unwrap_or("")
                    .to_string()
            };
            Some(QueryEnc::List {
                flattened,
                member_seg,
                flat_name,
                elem: Box::new(inner),
            })
        }
        ZapType::Dict(k, _) => {
            // Map keys are serialized as their (string/enum) value; a non-string
            // key is not serializable here.
            if **k != ZapType::Str && !matches!(**k, ZapType::Enum(_)) {
                return None;
            }
            let key_ref = shape.and_then(|s| s.key.clone());
            let val_ref = shape.and_then(|s| s.value.clone())?;
            let flattened = flavor == QueryFlavor::Ec2
                || r.flattened
                || shape.map(|s| s.flattened).unwrap_or(false);
            let key_name = key_ref
                .as_ref()
                .map(|kr| suffix_name(flavor, kr, "key"))
                .unwrap_or_else(|| "key".to_string());
            let value_name = suffix_name(flavor, &val_ref, "value");
            let val_ty = resolve(model, &val_ref.shape);
            let val_shape = model.shape(&val_ref.shape);
            if let Some(text) = scalar_text(&val_ty, &val_ref, val_shape) {
                return Some(QueryEnc::ScalarMap {
                    flattened,
                    key_name,
                    value_name,
                    value: text,
                });
            }
            let inner = plan_enc(model, &val_ref, flavor, serializable)?;
            // A map of lists/maps is not representable with one index loop.
            if matches!(
                inner,
                QueryEnc::ScalarList { .. }
                    | QueryEnc::List { .. }
                    | QueryEnc::ScalarMap { .. }
                    | QueryEnc::Map { .. }
            ) {
                return None;
            }
            Some(QueryEnc::Map {
                flattened,
                key_name,
                value_name,
                value: Box::new(inner),
            })
        }
        scalar => Some(QueryEnc::Scalar(scalar_text(scalar, r, shape)?)),
    }
}

/// Compute, for every structure shape, whether the query emitter can serialize
/// it (every member plans an encoding). Collections of serializable elements are
/// fine. Computed to a fixpoint so recursive shapes settle correctly.
pub fn compute_query_serializable(model: &Model, flavor: QueryFlavor) -> HashMap<String, bool> {
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
                .all(|r| plan_enc(model, r, flavor, &verdict).is_some());
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

/// Plan the query/ec2 serialization for `op`, or a short reason it must be
/// skipped. `serializable` is the model-wide struct verdict (fixpoint).
pub fn plan_query(
    model: &Model,
    op: &Operation,
    flavor: QueryFlavor,
    serializable: &HashMap<String, bool>,
) -> Result<QueryOp, String> {
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
        let enc = plan_enc(model, r, flavor, serializable).ok_or_else(|| skip_reason(model, r))?;
        plan.members.push(QueryMember {
            key,
            field,
            optional,
            enc,
        });
    }

    Ok(plan)
}

/// A short human reason a member could not be planned (for the skip list).
fn skip_reason(model: &Model, r: &ShapeRef) -> String {
    match resolve(model, &r.shape) {
        ZapType::Dict(k, _) if *k != ZapType::Str && !matches!(*k, ZapType::Enum(_)) => {
            "a map with a non-string key".to_string()
        }
        ZapType::List(_) => "a list of lists/maps".to_string(),
        ZapType::Dict(..) => "a map of lists/maps".to_string(),
        other => format!("an unsupported member type {}", other.render()),
    }
}

// ---------------------------------------------------------------------------
// Emission: per-shape `<shape>_to_query` functions + the recursive value emitter
// ---------------------------------------------------------------------------

/// A running form-parameter key: a compile-time literal (the common case — folds
/// into one quoted string) or a runtime Zap expression (inside index loops).
#[derive(Clone)]
enum Key {
    Lit(String),
    Dyn(String),
}

impl Key {
    /// The Zap expression for this key (a quoted literal, or the raw expression).
    fn expr(&self) -> String {
        match self {
            Key::Lit(s) => format!("\"{s}\""),
            Key::Dyn(e) => e.clone(),
        }
    }
    /// Append a static `.seg` path segment.
    fn seg(&self, seg: &str) -> Key {
        match self {
            Key::Lit(s) => Key::Lit(format!("{s}.{seg}")),
            Key::Dyn(e) => Key::Dyn(format!("{e} + \".{seg}\"")),
        }
    }
    /// Append a runtime 1-based index segment (the loop variable `iv`).
    fn index(&self, iv: &str) -> Key {
        match self {
            Key::Lit(s) => Key::Dyn(format!("\"{s}.\" + str({iv})")),
            Key::Dyn(e) => Key::Dyn(format!("{e} + \".\" + str({iv})")),
        }
    }
}

/// The emitter for the per-shape query serializers a service needs, plus the
/// recursive value emitter shared with the client method's top-level members.
pub struct QuerySer<'a> {
    model: &'a Model,
    flavor: QueryFlavor,
    serializable: &'a HashMap<String, bool>,
    /// shape name -> emitted serializer function name (collision-free).
    fn_names: HashMap<String, String>,
}

impl<'a> QuerySer<'a> {
    pub fn new(
        model: &'a Model,
        flavor: QueryFlavor,
        serializable: &'a HashMap<String, bool>,
    ) -> Self {
        QuerySer {
            model,
            flavor,
            serializable,
            fn_names: HashMap::new(),
        }
    }

    /// Collect every structure reachable (through struct / list / map members)
    /// from the given input root shapes that needs a serializer function, and
    /// assign each a collision-free name. Call once before `emit_serializers`.
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
            // A nested struct is a serializer-function root; a root input shape
            // is inlined in the method, so only its nested structs need funcs.
            for r in shape.members.values() {
                for dep in reachable_struct_names(self.model, r) {
                    if *self.serializable.get(&dep).unwrap_or(&false) {
                        order.push(dep.clone());
                    }
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
            let base = format!("{}_to_query", snake_case(name));
            let unique = unique_name(&base, &used);
            used.push(unique.clone());
            self.fn_names.insert(name.clone(), unique);
        }
    }

    fn fn_name(&self, shape_name: &str) -> String {
        self.fn_names
            .get(shape_name)
            .cloned()
            .unwrap_or_else(|| format!("{}_to_query", snake_case(shape_name)))
    }

    /// Emit every planned serializer function, in deterministic order.
    pub fn emit_serializers(&self) -> String {
        let mut names: Vec<&String> = self.fn_names.keys().collect();
        names.sort();
        let mut out = String::new();
        for name in names {
            out.push_str(&self.emit_struct_fn(name));
            out.push('\n');
        }
        out
    }

    fn emit_struct_fn(&self, name: &str) -> String {
        let shape = self.model.shape(name).unwrap();
        let ty = escape_ident(name).0;
        let func = self.fn_name(name);
        let mut out = String::new();
        out.push_str(&format!(
            "# Serialize {name} into the query form parameters under `prefix`.\n"
        ));
        out.push_str(&format!(
            "def {func}(list[query.QueryPair] p, str prefix, {ty} v) -> list[query.QueryPair]:\n"
        ));
        if shape.members.is_empty() {
            out.push_str(&format!("{IND}return p\n"));
            return out;
        }
        let mut ctr: u32 = 0;
        for (mn, r) in &shape.members {
            let enc = match plan_enc(self.model, r, self.flavor, self.serializable) {
                Some(e) => e,
                None => continue, // guarded by `serializable`
            };
            let field = escape_ident(mn).0;
            let wire = serialized_name(self.flavor, mn, r);
            let optional = !shape.required.contains(mn);
            // Member key = prefix.wire, built at runtime via the codec's query_key.
            let key = Key::Dyn(format!("query.query_key(prefix, \"{wire}\")"));
            self.emit_value(
                &mut out,
                IND,
                &key,
                &format!("v.{field}"),
                optional,
                &enc,
                &mut ctr,
            );
        }
        out.push_str(&format!("{IND}return p\n"));
        out
    }

    /// Emit the statements that serialize one top-level input member (literal
    /// key, `input.<field>` access) into `p`. Used by the client method.
    pub fn emit_top_member(&self, out: &mut String, indent: &str, m: &QueryMember, ctr: &mut u32) {
        let key = Key::Lit(m.key.clone());
        self.emit_value(
            out,
            indent,
            &key,
            &format!("input.{}", m.field),
            m.optional,
            &m.enc,
            ctr,
        );
    }

    /// Recursively emit the parameter appends for `access` under encoding `enc`
    /// at key `key`. An optional member is guarded first.
    #[allow(clippy::too_many_arguments)]
    fn emit_value(
        &self,
        out: &mut String,
        indent: &str,
        key: &Key,
        access: &str,
        optional: bool,
        enc: &QueryEnc,
        ctr: &mut u32,
    ) {
        if optional {
            match enc {
                // Collections take a default; scalars/structs guard + unwrap.
                QueryEnc::ScalarList { .. } | QueryEnc::List { .. } => {
                    let v = format!("{access}.unwrap_or([])");
                    self.emit_value_inner(out, indent, key, &v, enc, ctr);
                }
                QueryEnc::ScalarMap { .. } | QueryEnc::Map { .. } => {
                    let v = format!("{access}.unwrap_or({{}})");
                    self.emit_value_inner(out, indent, key, &v, enc, ctr);
                }
                _ => {
                    out.push_str(&format!("{indent}if {access}.is_some():\n"));
                    let inner = format!("{indent}{IND}");
                    let v = format!("{access}.unwrap()");
                    self.emit_value_inner(out, &inner, key, &v, enc, ctr);
                }
            }
        } else {
            self.emit_value_inner(out, indent, key, access, enc, ctr);
        }
    }

    fn emit_value_inner(
        &self,
        out: &mut String,
        indent: &str,
        key: &Key,
        access: &str,
        enc: &QueryEnc,
        ctr: &mut u32,
    ) {
        match enc {
            QueryEnc::Scalar(text) => {
                let value = scalar_value_text(text, access);
                emit_line(
                    out,
                    indent,
                    &format!("p = query.query_scalar(p, {}, ", key.expr()),
                    &value,
                    ")",
                    ctr,
                );
            }
            QueryEnc::ScalarList {
                flattened,
                member_seg,
            } => {
                if *flattened {
                    emit_line(
                        out,
                        indent,
                        &format!("p = query.query_flat_list(p, {}, ", key.expr()),
                        access,
                        ")",
                        ctr,
                    );
                } else {
                    emit_line(
                        out,
                        indent,
                        &format!("p = query.query_list(p, {}, \"{member_seg}\", ", key.expr()),
                        access,
                        ")",
                        ctr,
                    );
                }
            }
            QueryEnc::List {
                flattened,
                member_seg,
                flat_name,
                elem,
            } => {
                // The list's name segment (wrapped: key.member_seg; flattened:
                // the element-renamed name, else the member key unchanged).
                let base = if *flattened {
                    if flat_name.is_empty() {
                        key.clone()
                    } else {
                        rename_last(key, flat_name)
                    }
                } else {
                    key.seg(member_seg)
                };
                let iv = format!("qi{}", next(ctr));
                let ev = format!("qe{}", next(ctr));
                out.push_str(&format!("{indent}auto {iv} = 1\n"));
                out.push_str(&format!("{indent}for {ev} in {access}:\n"));
                let inner = format!("{indent}{IND}");
                let elem_key = base.index(&iv);
                self.emit_value_inner(out, &inner, &elem_key, &ev, elem, ctr);
                out.push_str(&format!("{inner}{iv} = {iv} + 1\n"));
            }
            QueryEnc::ScalarMap {
                flattened,
                key_name,
                value_name,
                value,
            } => {
                let kv = format!("qk{}", next(ctr));
                let ksv = format!("qks{}", next(ctr));
                let vsv = format!("qvs{}", next(ctr));
                out.push_str(&format!("{indent}list[str] {ksv} = []\n"));
                out.push_str(&format!("{indent}list[str] {vsv} = []\n"));
                out.push_str(&format!("{indent}for {kv} in sorted({access}.keys()):\n"));
                let inner = format!("{indent}{IND}");
                out.push_str(&format!("{inner}{ksv}.append({kv})\n"));
                let vt = scalar_value_text(value, &format!("{access}[{kv}]"));
                out.push_str(&format!("{inner}{vsv}.append({vt})\n"));
                let helper = if *flattened {
                    "query_flat_map"
                } else {
                    "query_map"
                };
                emit_line(
                    out,
                    indent,
                    &format!(
                        "p = query.{helper}(p, {}, \"{key_name}\", \"{value_name}\", {ksv}, ",
                        key.expr()
                    ),
                    &vsv,
                    ")",
                    ctr,
                );
            }
            QueryEnc::Map {
                flattened,
                key_name,
                value_name,
                value,
            } => {
                // Per-entry prefix: Name.entry.N (wrapped) or Name.N (flattened).
                let entry_base = if *flattened {
                    key.clone()
                } else {
                    key.seg("entry")
                };
                let iv = format!("qi{}", next(ctr));
                let kv = format!("qk{}", next(ctr));
                out.push_str(&format!("{indent}auto {iv} = 1\n"));
                out.push_str(&format!("{indent}for {kv} in sorted({access}.keys()):\n"));
                let inner = format!("{indent}{IND}");
                let entry = entry_base.index(&iv);
                emit_line(
                    out,
                    &inner,
                    &format!("p = query.query_scalar(p, {}, ", entry.seg(key_name).expr()),
                    &kv,
                    ")",
                    ctr,
                );
                let val_key = entry.seg(value_name);
                self.emit_value_inner(
                    out,
                    &inner,
                    &val_key,
                    &format!("{access}[{kv}]"),
                    value,
                    ctr,
                );
                out.push_str(&format!("{inner}{iv} = {iv} + 1\n"));
            }
            QueryEnc::Struct(name) => {
                // A struct call is `p = fn(p, key, access)`; hoist only the
                // access when the line is long (never the comma-joined args).
                let fname = self.fn_name(name);
                let one = format!("{indent}p = {fname}(p, {}, {access})", key.expr());
                if one.chars().count() <= 88 {
                    out.push_str(&one);
                    out.push('\n');
                } else {
                    let tmp = format!("t{}", next(ctr));
                    out.push_str(&format!("{indent}auto {tmp} = {access}\n"));
                    out.push_str(&format!("{indent}p = {fname}(p, {}, {tmp})\n", key.expr()));
                }
            }
        }
    }
}

/// Replace the final path segment of `key` with `name` (botocore's flattened
/// list element-rename). Only reachable with a `Lit` key in practice (a nested
/// flattened list under a dynamic prefix is not planned).
fn rename_last(key: &Key, name: &str) -> Key {
    match key {
        Key::Lit(s) => {
            let mut parts: Vec<&str> = s.split('.').collect();
            if let Some(last) = parts.last_mut() {
                *last = name;
            }
            Key::Lit(parts.join("."))
        }
        Key::Dyn(_) => key.clone(),
    }
}

/// The scalar value expression for a query form parameter.
fn scalar_value_text(text: &ScalarText, access: &str) -> String {
    match text {
        ScalarText::Str => access.to_string(),
        ScalarText::Int | ScalarText::Float => format!("str({access})"),
        ScalarText::Bool => format!("query.query_bool({access})"),
        ScalarText::Blob => format!("query.query_blob({access})"),
        ScalarText::TimestampIso => format!("query.query_timestamp_iso8601({access})"),
        ScalarText::TimestampEpoch => format!("query.query_timestamp_epoch({access})"),
    }
}

/// Emit `{indent}{prefix}{value}{suffix}` on one line, or hoist `value` into a
/// fresh local when the line would exceed 88 columns (matches emit.rs posture).
fn emit_line(
    out: &mut String,
    indent: &str,
    prefix: &str,
    value: &str,
    suffix: &str,
    ctr: &mut u32,
) {
    let one = format!("{indent}{prefix}{value}{suffix}");
    if one.chars().count() <= 88 {
        out.push_str(&one);
        out.push('\n');
    } else {
        // `t{n}` (not a q-prefixed name) so pre-existing scalar / scalar-list
        // top-level emission stays byte-identical to the #354 output.
        let tmp = format!("t{}", next(ctr));
        out.push_str(&format!("{indent}auto {tmp} = {value}\n"));
        out.push_str(&format!("{indent}{prefix}{tmp}{suffix}\n"));
    }
}

fn next(ctr: &mut u32) -> u32 {
    let n = *ctr;
    *ctr += 1;
    n
}

/// The struct shape names directly reachable through a member reference (through
/// list element / map value nesting).
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

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = r#"{
      "metadata":{"protocol":"query","apiVersion":"2011-06-15","endpointPrefix":"svc"},
      "operations":{
        "DoThing":{"name":"DoThing","input":{"shape":"DoThingRequest"}},
        "Nested":{"name":"Nested","input":{"shape":"NestedRequest"}}
      },
      "shapes":{
        "S":{"type":"string"},
        "I":{"type":"integer"},
        "B":{"type":"boolean"},
        "FlatList":{"type":"list","member":{"shape":"S"},"flattened":true},
        "WrapList":{"type":"list","member":{"shape":"S"}},
        "StrMap":{"type":"map","key":{"shape":"S"},"value":{"shape":"S"}},
        "Tag":{"type":"structure","members":{"Key":{"shape":"S"},"Value":{"shape":"S"}}},
        "TagList":{"type":"list","member":{"shape":"Tag"}},
        "Inner":{"type":"structure","members":{"Name":{"shape":"S"},"Count":{"shape":"I"}}},
        "DoThingRequest":{"type":"structure","required":["Name"],"members":{
          "Name":{"shape":"S"},
          "Count":{"shape":"I"},
          "Flag":{"shape":"B"},
          "Flat":{"shape":"FlatList"},
          "Wrapped":{"shape":"WrapList"}}},
        "NestedRequest":{"type":"structure","members":{
          "Inner":{"shape":"Inner"},
          "Tags":{"shape":"TagList"},
          "Attrs":{"shape":"StrMap"}}}
      }}"#;

    fn verdict() -> (Model, HashMap<String, bool>) {
        let m = Model::from_json_str(M).unwrap();
        let v = compute_query_serializable(&m, QueryFlavor::Query);
        (m, v)
    }

    #[test]
    fn awsquery_scalar_and_list_members_unchanged() {
        let (m, v) = verdict();
        let p = plan_query(&m, &m.operations["DoThing"], QueryFlavor::Query, &v).unwrap();
        assert_eq!(p.action, "DoThing");
        assert_eq!(p.version, "2011-06-15");
        assert!(matches!(
            &p.members[0].enc,
            QueryEnc::Scalar(ScalarText::Str)
        ));
        assert!(matches!(
            &p.members[1].enc,
            QueryEnc::Scalar(ScalarText::Int)
        ));
        assert!(matches!(
            &p.members[2].enc,
            QueryEnc::Scalar(ScalarText::Bool)
        ));
        assert!(matches!(
            &p.members[3].enc,
            QueryEnc::ScalarList {
                flattened: true,
                ..
            }
        ));
        assert!(matches!(
            &p.members[4].enc,
            QueryEnc::ScalarList {
                flattened: false,
                ..
            }
        ));
    }

    #[test]
    fn plans_nested_struct_list_of_structs_and_map() {
        let (m, v) = verdict();
        assert!(v["NestedRequest"]);
        assert!(v["Inner"]);
        assert!(v["Tag"]);
        let p = plan_query(&m, &m.operations["Nested"], QueryFlavor::Query, &v).unwrap();
        assert!(matches!(&p.members[0].enc, QueryEnc::Struct(n) if n == "Inner"));
        match &p.members[1].enc {
            QueryEnc::List {
                flattened, elem, ..
            } => {
                assert!(!flattened);
                assert!(matches!(**elem, QueryEnc::Struct(ref n) if n == "Tag"));
            }
            other => panic!("expected list of structs, got {other:?}"),
        }
        assert!(matches!(
            &p.members[2].enc,
            QueryEnc::ScalarMap {
                flattened: false,
                ..
            }
        ));
    }

    #[test]
    fn emits_nested_serializer_function() {
        let (m, v) = verdict();
        let mut ser = QuerySer::new(&m, QueryFlavor::Query, &v);
        ser.plan_roots(&["NestedRequest".to_string()]);
        let src = ser.emit_serializers();
        assert!(src.contains("def inner_to_query(list[query.QueryPair] p, str prefix, Inner v)"));
        assert!(src.contains("def tag_to_query(list[query.QueryPair] p, str prefix, Tag v)"));
        assert!(src.contains("query.query_key(prefix, \"Name\")"));
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
        let v = compute_query_serializable(&m, QueryFlavor::Ec2);
        let p = plan_query(&m, &m.operations["Op"], QueryFlavor::Ec2, &v).unwrap();
        assert_eq!(p.members[0].key, "DryRun");
        assert!(matches!(
            &p.members[0].enc,
            QueryEnc::Scalar(ScalarText::Bool)
        ));
        assert_eq!(p.members[1].key, "InstanceId");
        assert!(matches!(
            &p.members[1].enc,
            QueryEnc::ScalarList {
                flattened: true,
                ..
            }
        ));
    }
}
