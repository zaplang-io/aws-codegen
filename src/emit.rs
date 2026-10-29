//! Zap source emission from a parsed model.
//!
//! The generated file mirrors the hand-written `aws.dynamodb` client: a
//! protocol constructor, one `@derive(Json)` struct per modeled shape, open
//! enums for string enums, a service error enum + code classifier, and a client
//! struct whose methods build the input shape and dispatch through the
//! `aws.awsjson` codec, returning ready-to-send signed request text.

use crate::binding::{plan_operation, OpBinding, PayloadBody, ScalarBind};
use crate::model::{Model, Paginators, Shape};
use crate::naming::{escape_ident, snake_case};
use crate::types::{compute_derivable, resolve, ZapType};
use std::collections::{HashMap, HashSet};

/// The wire protocol the generator emits for a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    /// awsJson 1.0 / 1.1 — RPC-style, whole input shape as one JSON POST body.
    AwsJson,
    /// rest-json (restJson1) — members bound to URI/query/header/payload.
    RestJson,
}

/// What the generator covered, for the file header and the CLI summary.
#[derive(Debug, Default, Clone)]
pub struct Coverage {
    pub operations_total: usize,
    pub operations_methods: usize,
    pub operations_skipped: usize,
    pub structs_total: usize,
    pub structs_derivable: usize,
    pub enums: usize,
    pub error_variants: usize,
    /// Paginated operations that got a generated `paginate_*` iterator.
    pub paginators: usize,
    /// Paginated operations we could not surface (non-derivable input or a
    /// token that is not a simple string field).
    pub paginators_skipped: usize,
}

const IND: &str = "    ";

/// Emit the full Zap client for `model`, driving paginators off `paginators`
/// (pass `&Paginators::default()` for none). Returns the source and a coverage
/// summary.
pub fn generate(model: &Model, paginators: &Paginators) -> (String, Coverage) {
    let g = Generator::new(model, paginators);
    g.run()
}

struct Generator<'a> {
    model: &'a Model,
    paginators: &'a Paginators,
    derivable: HashMap<String, bool>,
    /// Type-name prefix for client/error (serviceId, else PascalCase prefix).
    type_prefix: String,
    /// snake prefix for free functions (endpointPrefix).
    fn_prefix: String,
    /// awsJson vs rest-json dispatch.
    protocol: Protocol,
    /// rest-json: the set of shapes used as an operation input, so their bound
    /// (uri/query/header) members can be rendered as the plain wire type (a
    /// string enum becomes `str`) in the parameter-carrier struct.
    rest_input_shapes: HashSet<String>,
}

impl<'a> Generator<'a> {
    fn new(model: &'a Model, paginators: &'a Paginators) -> Self {
        let md = &model.metadata;
        let type_prefix = if !md.service_id.is_empty() {
            escape_ident(&md.service_id).0
        } else {
            pascal(&md.endpoint_prefix)
        };
        let fn_prefix = snake_case(if !md.endpoint_prefix.is_empty() {
            &md.endpoint_prefix
        } else {
            &md.service_id
        });
        let protocol = match md.protocol.trim() {
            "rest-json" => Protocol::RestJson,
            _ => Protocol::AwsJson,
        };
        let rest_input_shapes = if protocol == Protocol::RestJson {
            model
                .operations
                .values()
                .filter_map(|op| op.input.as_ref().map(|r| r.shape.clone()))
                .collect()
        } else {
            HashSet::new()
        };
        Generator {
            model,
            paginators,
            derivable: compute_derivable(model),
            type_prefix,
            fn_prefix,
            protocol,
            rest_input_shapes,
        }
    }

    /// The SigV4 signing name: `signingName` when the model sets one, else the
    /// endpoint prefix. For rest-json this is also used as the host service
    /// (they coincide for Lambda and most rest-json services).
    fn sigv4_service(&self) -> String {
        let md = &self.model.metadata;
        if !md.signing_name.is_empty() {
            md.signing_name.clone()
        } else {
            md.endpoint_prefix.clone()
        }
    }

    fn is_derivable(&self, shape_name: &str) -> bool {
        *self.derivable.get(shape_name).unwrap_or(&false)
    }

    fn run(&self) -> (String, Coverage) {
        let mut cov = Coverage::default();
        let enums = self.enum_section(&mut cov);
        let shapes = self.shape_section(&mut cov);
        let errors = self.error_section(&mut cov);
        let client = self.client_section(&mut cov);

        let mut out = String::new();
        out.push_str(&self.header(&cov));
        out.push('\n');
        out.push_str(&self.protocol_fn());
        out.push('\n');
        if !enums.is_empty() {
            out.push_str(
                "# --- enums -----------------------------------------------------------------\n\n",
            );
            out.push_str(&enums);
        }
        out.push_str(
            "# --- shapes ----------------------------------------------------------------\n\n",
        );
        out.push_str(&shapes);
        out.push_str(
            "# --- errors ----------------------------------------------------------------\n\n",
        );
        out.push_str(&errors);
        out.push('\n');
        out.push_str(
            "# --- client ----------------------------------------------------------------\n\n",
        );
        out.push_str(&client);
        (out, cov)
    }

    fn header(&self, cov: &Coverage) -> String {
        let md = &self.model.metadata;
        let version = json_wire_version(&md.json_version);
        let mut h = String::new();
        let bar = "# ===========================================================================\n";
        h.push_str(bar);
        h.push_str("# GENERATED by aws-codegen (zaplang-io/aws-codegen). DO NOT EDIT BY HAND.\n");
        h.push_str("# Regenerate with: aws-codegen <service-2.json> -o <out.zap>\n");
        h.push_str("#\n");
        h.push_str(&format!(
            "# Service: {} (serviceId {}, API {})\n",
            nonempty(&md.service_full_name, &md.service_id),
            md.service_id,
            md.api_version
        ));
        match self.protocol {
            Protocol::AwsJson => h.push_str(&format!(
                "# Protocol: awsJson {} (targetPrefix {})\n",
                version, md.target_prefix
            )),
            Protocol::RestJson => h.push_str(&format!(
                "# Protocol: rest-json (restJson1) (SigV4 service {})\n",
                self.sigv4_service()
            )),
        }
        h.push_str("# Source: botocore service-2.json (Apache-2.0); documentation stripped.\n");
        h.push_str("#\n");
        match self.protocol {
            Protocol::AwsJson => h.push_str(
                "# Depends on aws.core + aws.awsjson (bundle them ahead of this file; there is\n",
            ),
            Protocol::RestJson => h.push_str(
                "# Depends on aws.core + aws.binding + aws.restjson (bundle them ahead of this\n# file; there is\n",
            ),
        }
        h.push_str("# no `import` yet). Each operation returns ready-to-send, SigV4-signed\n");
        match self.protocol {
            Protocol::AwsJson => h.push_str(
                "# HTTP/1.1 request text, matching the hand-written aws.dynamodb client.\n",
            ),
            Protocol::RestJson => h.push_str(
                "# HTTP/1.1 request text: members bind to the URI path/query/headers and the\n# remaining members (or an httpPayload member) form the body.\n",
            ),
        }
        h.push_str("# Paginators additionally use the live transport (aws.core `send` /\n");
        h.push_str(
            "# `regional_host` / `next_page_json`) to walk pages and yield each Response.\n",
        );
        h.push_str("#\n");
        match self.protocol {
            Protocol::AwsJson => {
                h.push_str(&format!(
                    "# Coverage (v0, awsJson only): {} operations — {} with a generated method,\n",
                    cov.operations_total, cov.operations_methods
                ));
                h.push_str(&format!(
                    "#   {} skipped (input uses collections not yet serializable by derive).\n",
                    cov.operations_skipped
                ));
            }
            Protocol::RestJson => {
                h.push_str(&format!(
                    "# Coverage (rest-json): {} operations — {} with a generated method,\n",
                    cov.operations_total, cov.operations_methods
                ));
                h.push_str(&format!(
                    "#   {} skipped (a member type is not yet bindable/serializable by derive).\n",
                    cov.operations_skipped
                ));
            }
        }
        h.push_str(&format!(
            "#   {} structs ({} @derive(Json)), {} enums, {} error variants.\n",
            cov.structs_total, cov.structs_derivable, cov.enums, cov.error_variants
        ));
        h.push_str(&format!(
            "#   {} paginators generated ({} paginated ops skipped) from paginators-1.json.\n",
            cov.paginators, cov.paginators_skipped
        ));
        h.push_str("# @derive(Json) is attached to structs whose members are all derive-\n");
        h.push_str("# serializable; structs containing list/map members are emitted plain,\n");
        h.push_str("# pending derive collection support (zaplang-io/zap#346 follow-up).\n");
        h.push_str(bar);
        h
    }

    fn protocol_fn(&self) -> String {
        let md = &self.model.metadata;
        if self.protocol == Protocol::RestJson {
            let svc = self.sigv4_service();
            return format!(
                "# The {} rest-json protocol: SigV4 service \"{}\" (also the endpoint\n# prefix for host resolution). Each operation binds its input members to the\n# URI path/query/headers and dispatches through the aws.restjson codec.\ndef {}_service() -> str:\n{IND}return \"{}\"\n",
                self.type_prefix, svc, self.fn_prefix, svc,
            );
        }
        let ctor = if md.json_version.trim() == "1.1" {
            "awsjson_1_1"
        } else {
            "awsjson_1_0"
        };
        format!(
            "# The {} awsJson protocol: version {}, API id \"{}\".\ndef {}_protocol() -> AwsJson:\n{IND}return {}(\"{}\", \"{}\")\n",
            self.type_prefix,
            json_wire_version(&md.json_version),
            md.target_prefix,
            self.fn_prefix,
            ctor,
            md.target_prefix,
            md.endpoint_prefix,
        )
    }

    // --- enums -------------------------------------------------------------

    fn enum_section(&self, cov: &mut Coverage) -> String {
        let mut out = String::new();
        for name in self.model.sorted_shape_names() {
            let shape = self.model.shape(name).unwrap();
            if !shape.is_enum() {
                continue;
            }
            out.push_str(&self.emit_enum(name, shape));
            out.push('\n');
            cov.enums += 1;
        }
        out
    }

    fn emit_enum(&self, name: &str, shape: &Shape) -> String {
        let type_name = escape_ident(name).0;
        let mut out = String::new();
        out.push_str("@derive(Json)\n@json(open)\n");
        out.push_str(&format!("enum {type_name}:\n"));
        let mut used: Vec<String> = Vec::new();
        for v in shape.enum_values.as_ref().unwrap() {
            let variant = unique(&escape_ident(v).0, &used);
            used.push(variant.clone());
            out.push_str(&format!("{IND}{variant}\n"));
        }
        // The forward-compatible fallback (exactly one, carrying the raw string).
        let fallback = unique("Unknown", &used);
        out.push_str(&format!("{IND}{fallback}(str value)\n"));
        out
    }

    // --- shapes ------------------------------------------------------------

    fn shape_section(&self, cov: &mut Coverage) -> String {
        let mut out = String::new();
        for name in self.model.sorted_shape_names() {
            let shape = self.model.shape(name).unwrap();
            if !shape.is_structure() {
                continue;
            }
            out.push_str(&self.emit_struct(name, shape));
            out.push('\n');
            cov.structs_total += 1;
            if self.is_derivable(name) {
                cov.structs_derivable += 1;
            }
        }
        out
    }

    fn emit_struct(&self, name: &str, shape: &Shape) -> String {
        if self.protocol == Protocol::RestJson && self.rest_input_shapes.contains(name) {
            return self.emit_rest_input_struct(name, shape);
        }
        let type_name = escape_ident(name).0;
        let derivable = self.is_derivable(name);
        let mut out = String::new();

        // A non-derivable struct: explain which member(s) blocked the derive.
        if !derivable {
            let blockers: Vec<String> = shape
                .members
                .iter()
                .filter_map(|(mn, r)| {
                    let ty = resolve(self.model, &r.shape);
                    if member_blocks_derive(self.model, &ty, &self.derivable) {
                        Some(format!("{mn}: {}", ty.render()))
                    } else {
                        None
                    }
                })
                .collect();
            out.push_str(&format!(
                "# no @derive(Json): member(s) {} not yet serializable by derive\n",
                if blockers.is_empty() {
                    "(collection/nested)".to_string()
                } else {
                    blockers.join(", ")
                }
            ));
            out.push_str("# (list/map collections — zaplang-io/zap#346 follow-up).\n");
        } else {
            out.push_str("@derive(Json)\n");
        }
        out.push_str(&format!("struct {type_name}:\n"));

        if shape.members.is_empty() {
            // Zap has no empty block; a reserved Optional field keeps the struct
            // valid and (when derived) serializes to `{}` while it stays None.
            out.push_str(&format!(
                "{IND}# empty shape in the model; reserved field keeps it valid (sends nothing)\n"
            ));
            out.push_str(&format!("{IND}Optional[str] reserved\n"));
            return out;
        }

        for (mn, r) in &shape.members {
            let (field, changed) = escape_ident(mn);
            let ty = resolve(self.model, &r.shape);
            let optional = !shape.required.contains(mn);

            if changed {
                out.push_str(&format!(
                    "{IND}# wire name \"{mn}\" differs from field; derive rename is a #346 follow-up\n"
                ));
            }
            // Timestamp format annotation (only meaningful inside a derived struct).
            if derivable && ty == ZapType::DateTime {
                let fmt = r.timestamp_format.as_deref().or(self
                    .model
                    .shape(&r.shape)
                    .and_then(|s| s.timestamp_format.as_deref()));
                match fmt {
                    Some("iso8601") => {
                        out.push_str(&format!("{IND}@json(timestamp=\"iso8601\")\n"))
                    }
                    Some(other) if other != "unixTimestamp" => out.push_str(&format!(
                        "{IND}# timestampFormat \"{other}\" unsupported; encoded as epoch\n"
                    )),
                    _ => {}
                }
            }
            let rendered = if optional {
                format!("Optional[{}]", ty.render())
            } else {
                ty.render()
            };
            out.push_str(&format!("{IND}{rendered} {field}\n"));
        }
        out
    }

    /// Emit a rest-json operation input shape as a plain parameter-carrier
    /// struct (never serialized as a whole, so not `@derive(Json)`). A member
    /// bound to the URI/query/header that is a string enum is rendered as `str`,
    /// the plain wire type — the binding layer sends it verbatim and the enum
    /// constraint is advisory. Unbound (document) members keep their real type,
    /// so the per-operation `@derive(Json)` document struct can copy them.
    fn emit_rest_input_struct(&self, name: &str, shape: &Shape) -> String {
        let type_name = escape_ident(name).0;
        let mut out = String::new();
        out.push_str(&format!(
            "# rest-json request for {name}: members bind to the URI/query/headers or the\n# body (see the client method). A parameter carrier, not a JSON document.\n"
        ));
        out.push_str(&format!("struct {type_name}:\n"));

        if shape.members.is_empty() {
            out.push_str(&format!(
                "{IND}# empty shape in the model; reserved field keeps it valid\n"
            ));
            out.push_str(&format!("{IND}Optional[str] reserved\n"));
            return out;
        }

        for (mn, r) in &shape.members {
            let (field, changed) = escape_ident(mn);
            let real = resolve(self.model, &r.shape);
            let bound_slot = matches!(
                r.location.as_deref(),
                Some("uri") | Some("querystring") | Some("header")
            );
            // A string enum in a bound slot is carried as its plain wire string.
            let (ty_render, enum_note) = match (&real, bound_slot) {
                (ZapType::Enum(e), true) => ("str".to_string(), Some(e.clone())),
                _ => (real.render(), None),
            };
            if let Some(e) = enum_note {
                out.push_str(&format!(
                    "{IND}# wire string of the {e} enum ({} binding)\n",
                    r.location.as_deref().unwrap_or("")
                ));
            }
            if changed {
                out.push_str(&format!(
                    "{IND}# wire name \"{mn}\" differs from field; derive rename is a #346 follow-up\n"
                ));
            }
            let optional = !shape.required.contains(mn);
            let rendered = if optional {
                format!("Optional[{ty_render}]")
            } else {
                ty_render
            };
            out.push_str(&format!("{IND}{rendered} {field}\n"));
        }
        out
    }

    // --- errors ------------------------------------------------------------

    fn error_section(&self, cov: &mut Coverage) -> String {
        // Union of every operation's errors (operation-level + service-level all
        // surface the same way through the codec's __type handling).
        let mut names: Vec<String> = Vec::new();
        for op in self.model.operations.values() {
            for e in &op.errors {
                if !names.contains(&e.shape) {
                    names.push(e.shape.clone());
                }
            }
        }
        names.sort();
        cov.error_variants = names.len();

        let enum_name = format!("{}Error", self.type_prefix);
        let code_source = match self.protocol {
            Protocol::AwsJson => "awsJson `__type` / X-Amzn-ErrorType",
            Protocol::RestJson => "restJson1 X-Amzn-ErrorType / body `__type`",
        };
        let mut out = String::new();
        out.push_str(&format!(
            "# Service error set (operation + service level), dispatched from the\n# {code_source} code by {}_error_from_code.\n",
            self.fn_prefix
        ));
        out.push_str(&format!("enum {enum_name}:\n"));
        let mut variants: Vec<(String, String)> = Vec::new(); // (wire code, variant)
        let mut used: Vec<String> = Vec::new();
        for n in &names {
            let variant = unique(&escape_ident(n).0, &used);
            used.push(variant.clone());
            variants.push((n.clone(), variant.clone()));
            out.push_str(&format!("{IND}{variant}\n"));
        }
        let fallback = unique("Unknown", &used);
        out.push_str(&format!("{IND}{fallback}(str code)\n\n"));

        // Classifier: wire code -> variant.
        let classifier_doc = match self.protocol {
            Protocol::AwsJson => {
                "# Map an awsJson error code (the stripped __type shape name) to a variant.".to_string()
            }
            Protocol::RestJson => {
                "# Map a restJson1 error code (from rest_json_error_code: the X-Amzn-ErrorType\n# header or body __type, stripped to the bare shape name) to a variant.".to_string()
            }
        };
        out.push_str(&format!(
            "{classifier_doc}\ndef {}_error_from_code(str code) -> {enum_name}:\n",
            self.fn_prefix
        ));
        if variants.is_empty() {
            out.push_str(&format!("{IND}return {enum_name}.{fallback}(code=code)\n"));
        } else {
            for (wire, variant) in &variants {
                out.push_str(&format!("{IND}if code == \"{wire}\":\n"));
                out.push_str(&format!("{IND}{IND}return {enum_name}.{variant}\n"));
            }
            out.push_str(&format!("{IND}return {enum_name}.{fallback}(code=code)\n"));
        }
        out
    }

    // --- client ------------------------------------------------------------

    fn client_section(&self, cov: &mut Coverage) -> String {
        if self.protocol == Protocol::RestJson {
            return self.rest_client_section(cov);
        }
        let client_name = format!("{}Client", self.type_prefix);
        let mut methods = String::new();
        let mut skipped: Vec<String> = Vec::new();

        for op_name in self.model.sorted_operation_names() {
            cov.operations_total += 1;
            let op = &self.model.operations[op_name];
            let method = snake_case(op_name);
            let errors_doc = if op.errors.is_empty() {
                String::new()
            } else {
                let mut es: Vec<&str> = op.errors.iter().map(|e| e.shape.as_str()).collect();
                es.sort_unstable();
                format!("{IND}# errors: {}\n", es.join(", "))
            };

            // Decide the request body source.
            let input_shape = op.input.as_ref().map(|r| r.shape.as_str());
            let input_struct = input_shape.and_then(|s| {
                self.model
                    .shape(s)
                    .filter(|sh| sh.is_structure())
                    .map(|sh| (s, sh))
            });

            match input_struct {
                // Input with members, fully derivable -> serialize via to_json().
                Some((sname, sh)) if !sh.members.is_empty() && self.is_derivable(sname) => {
                    let ty = escape_ident(sname).0;
                    methods.push_str(&format!("{IND}# {op_name}\n"));
                    methods.push_str(&errors_doc);
                    methods.push_str(&format!(
                        "{IND}def {method}(self, {ty} input) -> str:\n{IND}{IND}auto body = input.to_json()\n"
                    ));
                    methods.push_str(&self.dispatch(op_name));
                    methods.push('\n');
                    cov.operations_methods += 1;
                }
                // Empty input, or no input shape -> empty JSON body, no parameter.
                Some((_, sh)) if sh.members.is_empty() => {
                    methods.push_str(&format!("{IND}# {op_name}\n"));
                    methods.push_str(&errors_doc);
                    methods.push_str(&format!(
                        "{IND}def {method}(self) -> str:\n{IND}{IND}auto body = \"{{}}\"\n"
                    ));
                    methods.push_str(&self.dispatch(op_name));
                    methods.push('\n');
                    cov.operations_methods += 1;
                }
                None => {
                    methods.push_str(&format!("{IND}# {op_name}\n"));
                    methods.push_str(&errors_doc);
                    methods.push_str(&format!(
                        "{IND}def {method}(self) -> str:\n{IND}{IND}auto body = \"{{}}\"\n"
                    ));
                    methods.push_str(&self.dispatch(op_name));
                    methods.push('\n');
                    cov.operations_methods += 1;
                }
                // Input with collection members -> skip (derive gap).
                Some((sname, _)) => {
                    skipped.push(format!("{op_name} (input {sname})"));
                    cov.operations_skipped += 1;
                }
            }
        }

        let (paginator_methods, paginators_skipped) = self.paginator_methods(cov);

        let mut out = String::new();
        if !skipped.is_empty() {
            out.push_str(
                "# Operations skipped in v0 (input shape has collection members not yet\n",
            );
            out.push_str(
                "# serializable by @derive(Json); pending zaplang-io/zap#346 follow-up):\n",
            );
            for s in &skipped {
                out.push_str(&format!("#   {s}\n"));
            }
            out.push('\n');
        }
        if !paginators_skipped.is_empty() {
            out.push_str(
                "# Paginated operations (paginators-1.json) not surfaced in v0 — their input\n",
            );
            out.push_str(
                "# is skipped above, or the continuation token is not a simple string field:\n",
            );
            for s in &paginators_skipped {
                out.push_str(&format!("#   {s}\n"));
            }
            out.push('\n');
        }
        out.push_str(&format!(
            "# A bound {} client: credentials + region, threaded into every operation.\n",
            self.type_prefix
        ));
        out.push_str(&format!("struct {client_name}:\n"));
        out.push_str(&format!("{IND}Credentials creds\n{IND}str region\n"));
        if methods.is_empty() && paginator_methods.is_empty() {
            // Defensive: keep the struct valid if nothing was derivable.
            out.push_str(&format!(
                "\n{IND}# no derivable-input operations were generated for this service in v0\n"
            ));
        } else {
            out.push('\n');
            out.push_str(&methods);
            out.push_str(&paginator_methods);
        }

        out.push_str(&format!(
            "# Construct a {} bound to credentials + region.\ndef {}_client(Credentials creds, str region) -> {client_name}:\n{IND}return {client_name}(creds=creds, region=region)\n",
            client_name, self.fn_prefix
        ));
        out
    }

    fn dispatch(&self, op_name: &str) -> String {
        format!(
            "{IND}{IND}return awsjson_request_now({}_protocol(), self.creds, self.region, \"{op_name}\", body)\n",
            self.fn_prefix
        )
    }

    // --- rest-json client --------------------------------------------------

    /// The rest-json counterpart to `client_section`: a method per operation
    /// that builds an `aws.binding` `HttpBinding` from the input members, plus a
    /// `@derive(Json)` document struct for each operation with a JSON body, and
    /// yield-based paginators. Operations whose members the binding layer cannot
    /// render yet are skipped with a documented reason (same posture as awsJson).
    fn rest_client_section(&self, cov: &mut Coverage) -> String {
        let client_name = format!("{}Client", self.type_prefix);
        let mut methods = String::new();
        let mut doc_structs = String::new();
        let mut skipped: Vec<String> = Vec::new();

        for op_name in self.model.sorted_operation_names() {
            cov.operations_total += 1;
            let op = &self.model.operations[op_name];
            match plan_operation(self.model, op, &self.derivable) {
                Ok(plan) => {
                    if let Some(ds) = self.rest_doc_struct(op_name, &plan) {
                        doc_structs.push_str(&ds);
                        doc_structs.push('\n');
                    }
                    methods.push_str(&self.rest_method(op_name, op, &plan));
                    methods.push('\n');
                    cov.operations_methods += 1;
                }
                Err(reason) => {
                    skipped.push(format!("{op_name} ({reason})"));
                    cov.operations_skipped += 1;
                }
            }
        }

        let (paginator_methods, paginators_skipped) = self.rest_paginator_methods(cov);

        let mut out = String::new();
        if !skipped.is_empty() {
            out.push_str(
                "# Operations skipped in v0 (a member type is not yet bindable/serializable —\n",
            );
            out.push_str(
                "# a non-string/enum/int URI/query/header, a collection or non-derivable\n",
            );
            out.push_str("# document member, or an unsupported httpPayload):\n");
            for s in &skipped {
                out.push_str(&format!("#   {s}\n"));
            }
            out.push('\n');
        }
        if !paginators_skipped.is_empty() {
            out.push_str(
                "# Paginated operations (paginators-1.json) not surfaced — their operation is\n",
            );
            out.push_str(
                "# skipped above, or the continuation token is not a simple string field:\n",
            );
            for s in &paginators_skipped {
                out.push_str(&format!("#   {s}\n"));
            }
            out.push('\n');
        }

        if !doc_structs.is_empty() {
            out.push_str(
                "# Per-operation JSON document bodies (the unbound \"document\" members of an\n# operation's input, serialized with @derive(Json)).\n\n",
            );
            out.push_str(&doc_structs);
        }

        out.push_str(&format!(
            "# A bound {} client: credentials + region, threaded into every operation.\n",
            self.type_prefix
        ));
        out.push_str(&format!("struct {client_name}:\n"));
        out.push_str(&format!("{IND}Credentials creds\n{IND}str region\n"));
        if methods.is_empty() && paginator_methods.is_empty() {
            out.push_str(&format!(
                "\n{IND}# no bindable operations were generated for this service in v0\n"
            ));
        } else {
            out.push('\n');
            out.push_str(&methods);
            out.push_str(&paginator_methods);
        }

        out.push_str(&format!(
            "# Construct a {} bound to credentials + region.\ndef {}_client(Credentials creds, str region) -> {client_name}:\n{IND}return {client_name}(creds=creds, region=region)\n",
            client_name, self.fn_prefix
        ));
        out
    }

    /// The `@derive(Json)` document struct for an operation with a JSON body —
    /// one field per unbound document member — or `None` when the operation has
    /// no document body (a GET/DELETE with everything bound, or a raw payload).
    fn rest_doc_struct(&self, op_name: &str, plan: &OpBinding) -> Option<String> {
        if !plan.has_document_body() {
            return None;
        }
        let name = format!("{}Document", escape_ident(op_name).0);
        let mut out = String::new();
        out.push_str(&format!(
            "@derive(Json)\nstruct {name}:\n{IND}# document members of {op_name}\n"
        ));
        for m in &plan.document {
            let rendered = if m.optional {
                format!("Optional[{}]", m.ty.render())
            } else {
                m.ty.render()
            };
            out.push_str(&format!("{IND}{rendered} {}\n", m.field));
        }
        Some(out)
    }

    /// Emit one rest-json operation method: assemble the labels/query/headers,
    /// attach the body (raw httpPayload, JSON document, or none), and sign.
    fn rest_method(&self, op_name: &str, op: &crate::model::Operation, plan: &OpBinding) -> String {
        let i2 = format!("{IND}{IND}");
        let i3 = format!("{IND}{IND}{IND}");
        let svc = &self.fn_prefix;
        let method = snake_case(op_name);

        let mut b = String::new();
        b.push_str(&format!(
            "{IND}# {op_name}  {} {}\n",
            plan.method, plan.path_template
        ));
        if !op.errors.is_empty() {
            let mut es: Vec<&str> = op.errors.iter().map(|e| e.shape.as_str()).collect();
            es.sort_unstable();
            b.push_str(&format!("{IND}# errors: {}\n", es.join(", ")));
        }
        match &plan.input_shape {
            Some(sh) => b.push_str(&format!("{IND}def {method}(self, {sh} input) -> str:\n")),
            None => b.push_str(&format!("{IND}def {method}(self) -> str:\n")),
        }
        b.push_str(&format!(
            "{i2}auto host = regional_host({svc}_service(), self.region)\n"
        ));

        // Non-greedy vs greedy labels.
        let greedy: Vec<&ScalarBind> = plan.labels.iter().filter(|l| l.greedy).collect();
        let plain: Vec<&ScalarBind> = plan.labels.iter().filter(|l| !l.greedy).collect();
        let labels_arg = self.rest_dict_local(&mut b, &i2, "labels", &plain);
        let greedy_arg = self.rest_dict_local(&mut b, &i2, "greedy_labels", &greedy);
        let query_arg =
            self.rest_dict_local(&mut b, &i2, "query", &plan.query.iter().collect::<Vec<_>>());
        let headers_arg = self.rest_dict_local(
            &mut b,
            &i2,
            "headers",
            &plan.headers.iter().collect::<Vec<_>>(),
        );

        let (pfx_arg, pmap_arg) = match &plan.prefix_headers {
            Some(ph) => {
                let map = if ph.optional {
                    format!("input.{}.unwrap_or({{}})", ph.field)
                } else {
                    format!("input.{}", ph.field)
                };
                (format!("\"{}\"", ph.prefix), map)
            }
            None => ("\"\"".to_string(), "{}".to_string()),
        };

        b.push_str(&format!(
            "{i2}auto b = HttpBinding(method=\"{}\", path_template=\"{}\", labels={labels_arg}, greedy_labels={greedy_arg}, query={query_arg}, headers={headers_arg}, prefix_header_prefix={pfx_arg}, prefix_headers={pmap_arg}, payload_kind=PayloadKind.Empty, body=\"\", content_type=\"\")\n",
            plan.method, plan.path_template
        ));

        // Attach the body and sign.
        let bind_var = if let Some(p) = &plan.payload {
            let (expr, ct) = match p.body {
                PayloadBody::Blob => (
                    if p.optional {
                        format!("str(input.{}.unwrap_or(bytes()))", p.field)
                    } else {
                        format!("str(input.{})", p.field)
                    },
                    "application/octet-stream",
                ),
                PayloadBody::Str => (
                    if p.optional {
                        format!("input.{}.unwrap_or(\"\")", p.field)
                    } else {
                        format!("input.{}", p.field)
                    },
                    "text/plain",
                ),
                PayloadBody::Document => {
                    (format!("input.{}.to_json()", p.field), "application/json")
                }
            };
            b.push_str(&format!(
                "{i2}auto bp = rest_json_raw_payload(b, {expr}, \"{ct}\")\n"
            ));
            "bp"
        } else if plan.has_document_body() {
            let doc = format!("{}Document", escape_ident(op_name).0);
            let fields: Vec<String> = plan
                .document
                .iter()
                .map(|m| format!("{}=input.{}", m.field, m.field))
                .collect();
            b.push_str(&format!("{i2}auto doc = {doc}({})\n", fields.join(", ")));
            b.push_str(&format!(
                "{i2}auto bp = rest_json_document(b, doc.to_json())\n"
            ));
            "bp"
        } else {
            "b"
        };

        b.push_str(&format!(
            "{i2}return rest_json_request(self.creds, {bind_var}, {svc}_service(), self.region, host)\n"
        ));
        let _ = i3;
        b
    }

    /// Declare a `dict[str, str]` local filled from the given scalar binds, and
    /// return the argument to pass to `HttpBinding` (the local name, or `{}`
    /// when there are no entries so no local is emitted). Optional members are
    /// only inserted when present, so an absent member sends nothing.
    fn rest_dict_local(
        &self,
        out: &mut String,
        indent: &str,
        local: &str,
        binds: &[&ScalarBind],
    ) -> String {
        if binds.is_empty() {
            return "{}".to_string();
        }
        out.push_str(&format!("{indent}dict[str, str] {local} = {{}}\n"));
        let i_inner = format!("{indent}{IND}");
        for s in binds {
            let access = format!("input.{}", s.field);
            if s.optional {
                let val = match s.ty {
                    ZapType::Int => format!("str({access}.unwrap_or(0))"),
                    _ => format!("{access}.unwrap_or(\"\")"),
                };
                out.push_str(&format!("{indent}if {access}.is_some():\n"));
                out.push_str(&format!("{i_inner}{local}[\"{}\"] = {val}\n", s.wire));
            } else {
                let val = match s.ty {
                    ZapType::Int => format!("str({access})"),
                    _ => access,
                };
                out.push_str(&format!("{indent}{local}[\"{}\"] = {val}\n", s.wire));
            }
        }
        local.to_string()
    }

    // --- rest-json paginators ----------------------------------------------

    /// Emit a `paginate_*` method for each paginated operation we can surface,
    /// plus the skipped list. A paginator qualifies when the operation already
    /// has a generated method and its `input_token`/`output_token` are each a
    /// single field whose input side is a `str` member of the input shape (so it
    /// threads via `input.<field> = Optional.Some(np.token)`). The request is
    /// built by calling the operation's own method, so the binding is reused.
    fn rest_paginator_methods(&self, cov: &mut Coverage) -> (String, Vec<String>) {
        let mut methods = String::new();
        let mut skipped: Vec<String> = Vec::new();
        for op_name in self.paginators.sorted_operation_names() {
            let pag = &self.paginators.pagination[op_name];
            match self.rest_plan_paginator(op_name, pag) {
                Ok(src) => {
                    methods.push_str(&src);
                    methods.push('\n');
                    cov.paginators += 1;
                }
                Err(reason) => {
                    skipped.push(format!("{op_name} ({reason})"));
                    cov.paginators_skipped += 1;
                }
            }
        }
        (methods, skipped)
    }

    fn rest_plan_paginator(
        &self,
        op_name: &str,
        pag: &crate::model::Paginator,
    ) -> Result<String, String> {
        let op = self
            .model
            .operations
            .get(op_name)
            .ok_or("not in service-2.json")?;
        // The operation must have a generated method.
        plan_operation(self.model, op, &self.derivable)
            .map_err(|_| "operation not generated".to_string())?;

        let input_ref = op.input.as_ref().ok_or("operation has no input")?;
        let input = self
            .model
            .shape(&input_ref.shape)
            .filter(|s| s.is_structure())
            .ok_or("input is not a structure")?;

        let input_token = pag
            .input_token
            .single()
            .ok_or("input_token is not a single field")?;
        let output_token = pag
            .output_token
            .single()
            .ok_or("output_token is not a single field")?;
        // The emitted loop reads the token with a flat `next_page_json` lookup, so
        // a nested JMESPath output_token would never terminate — skip it (as the
        // awsJson paginator path does).
        if !is_flat_field(output_token) {
            return Err(format!(
                "output_token {output_token} is a nested path, not a flat field"
            ));
        }
        let member = input
            .members
            .get(input_token)
            .ok_or_else(|| format!("input_token {input_token} is not a member of the input"))?;
        if resolve(self.model, &member.shape) != ZapType::Str {
            return Err(format!("input_token {input_token} is not a string field"));
        }

        let token_field = escape_ident(input_token).0;
        let token_optional = !input.required.contains(&input_token.to_string());
        let carry = if token_optional {
            "Optional.Some(np.token)".to_string()
        } else {
            "np.token".to_string()
        };
        let method = snake_case(op_name);
        let input_type = escape_ident(&input_ref.shape).0;
        let result_doc = if pag.result_key.is_empty() {
            String::new()
        } else {
            format!(" (result key: {})", pag.result_key.0.join(", "))
        };

        let svc = &self.fn_prefix;
        let mut out = String::new();
        out.push_str(&format!(
            "{IND}# Paginator for {op_name} — yields each Response page, threading the\n"
        ));
        out.push_str(&format!(
            "{IND}# {output_token} -> {token_field} continuation token until it is absent{result_doc}.\n"
        ));
        out.push_str(&format!(
            "{IND}def paginate_{method}(self, {input_type} input):\n"
        ));
        out.push_str(&format!(
            "{IND}{IND}auto host = regional_host({svc}_service(), self.region)\n"
        ));
        out.push_str(&format!("{IND}{IND}while True:\n"));
        out.push_str(&format!("{IND}{IND}{IND}auto raw = self.{method}(input)\n"));
        out.push_str(&format!("{IND}{IND}{IND}auto page = send(host, raw)\n"));
        out.push_str(&format!("{IND}{IND}{IND}yield page\n"));
        out.push_str(&format!(
            "{IND}{IND}{IND}auto np = next_page_json(page.body, \"{output_token}\")\n"
        ));
        out.push_str(&format!("{IND}{IND}{IND}if not np.has_more:\n"));
        out.push_str(&format!("{IND}{IND}{IND}{IND}break\n"));
        out.push_str(&format!("{IND}{IND}{IND}input.{token_field} = {carry}\n"));
        Ok(out)
    }

    // --- paginators --------------------------------------------------------

    /// Emit a `paginate_*` iterator method for every paginated operation we can
    /// surface, plus the list of paginated ops we skipped (with the reason).
    ///
    /// A paginator is generated only when the operation already has a generated
    /// method (derivable, non-empty input — so `input.to_json()` exists) and its
    /// `input_token`/`output_token` are each a single field whose input side is a
    /// `str` member of the input shape. That rules out DynamoDB's `Query`/`Scan`
    /// (non-derivable `AttributeValue`-map input; `ExclusiveStartKey` is a map,
    /// not a string) while surfacing the `List*` listings.
    fn paginator_methods(&self, cov: &mut Coverage) -> (String, Vec<String>) {
        let mut methods = String::new();
        let mut skipped: Vec<String> = Vec::new();

        for op_name in self.paginators.sorted_operation_names() {
            let pag = &self.paginators.pagination[op_name];
            match self.plan_paginator(op_name, pag) {
                Ok(plan) => {
                    methods.push_str(&plan.emit(&self.fn_prefix));
                    methods.push('\n');
                    cov.paginators += 1;
                }
                Err(reason) => {
                    skipped.push(format!("{op_name} ({reason})"));
                    cov.paginators_skipped += 1;
                }
            }
        }
        (methods, skipped)
    }

    /// Decide whether `op_name` can get a paginator, returning the emission plan
    /// or a short reason it was skipped.
    fn plan_paginator(
        &self,
        op_name: &str,
        pag: &crate::model::Paginator,
    ) -> Result<PaginatorPlan, String> {
        let op = self
            .model
            .operations
            .get(op_name)
            .ok_or("not in service-2.json")?;

        let input_shape = op.input.as_ref().map(|r| r.shape.as_str());
        let input_struct = input_shape.and_then(|s| {
            self.model
                .shape(s)
                .filter(|sh| sh.is_structure())
                .map(|sh| (s, sh))
        });
        let (input_name, input_sh) = match input_struct {
            Some((n, sh)) if !sh.members.is_empty() && self.is_derivable(n) => (n, sh),
            _ => return Err("input not derivable (no generated method)".to_string()),
        };

        let input_token = pag
            .input_token
            .single()
            .ok_or("input_token is not a single field")?;
        let output_token = pag
            .output_token
            .single()
            .ok_or("output_token is not a single field")?;

        // The output token must be a FLAT response field: the emitted loop reads
        // it with `next_page_json(page.body, "<output_token>")`, which looks up a
        // top-level string field, not a path. botocore sometimes writes a nested
        // JMESPath expression here (e.g. Kinesis DescribeStream's
        // `StreamDescription.Shards[-1].ShardId`); surfacing that verbatim would
        // emit a paginator that never finds the token and silently stops after
        // one page, so skip it rather than emit it wrong.
        if !is_flat_field(output_token) {
            return Err(format!(
                "output_token {output_token} is a nested path, not a flat field"
            ));
        }

        // The continuation token must be a string member of the input shape so we
        // can carry it on the next request.
        let member = input_sh
            .members
            .get(input_token)
            .ok_or_else(|| format!("input_token {input_token} is not a member of the input"))?;
        if resolve(self.model, &member.shape) != ZapType::Str {
            return Err(format!("input_token {input_token} is not a string field"));
        }
        let token_field = escape_ident(input_token).0;
        let token_optional = !input_sh.required.contains(&input_token.to_string());

        Ok(PaginatorPlan {
            op_name: op_name.to_string(),
            method: format!("paginate_{}", snake_case(op_name)),
            input_type: escape_ident(input_name).0,
            token_field,
            token_optional,
            output_token: output_token.to_string(),
            result_keys: pag.result_key.0.clone(),
        })
    }
}

/// A ready-to-emit paginator for one operation.
struct PaginatorPlan {
    op_name: String,
    method: String,
    input_type: String,
    /// The emitted input field that carries the continuation token.
    token_field: String,
    /// Whether that field is `Optional[str]` (vs a bare required `str`).
    token_optional: bool,
    /// The response body field holding the next token (wire name, read verbatim).
    output_token: String,
    /// Result key(s) the page's items live under — documentation only in v0.
    result_keys: Vec<String>,
}

impl PaginatorPlan {
    fn emit(&self, fn_prefix: &str) -> String {
        let result_doc = if self.result_keys.is_empty() {
            String::new()
        } else {
            format!(" (result key: {})", self.result_keys.join(", "))
        };
        let carry = if self.token_optional {
            "Optional.Some(np.token)".to_string()
        } else {
            "np.token".to_string()
        };
        let mut out = String::new();
        out.push_str(&format!(
            "{IND}# Paginator for {} — yields each Response page, threading the\n",
            self.op_name
        ));
        out.push_str(&format!(
            "{IND}# {} -> {} continuation token until the output token is absent{}.\n",
            self.output_token, self.token_field, result_doc
        ));
        out.push_str(&format!(
            "{IND}def {}(self, {} input):\n",
            self.method, self.input_type
        ));
        out.push_str(&format!(
            "{IND}{IND}auto host = regional_host({fn_prefix}_protocol().service, self.region)\n"
        ));
        out.push_str(&format!("{IND}{IND}while True:\n"));
        out.push_str(&format!("{IND}{IND}{IND}auto body = input.to_json()\n"));
        out.push_str(&format!(
            "{IND}{IND}{IND}auto raw = awsjson_request_now({fn_prefix}_protocol(), self.creds, self.region, \"{}\", body)\n",
            self.op_name
        ));
        out.push_str(&format!("{IND}{IND}{IND}auto page = send(host, raw)\n"));
        out.push_str(&format!("{IND}{IND}{IND}yield page\n"));
        out.push_str(&format!(
            "{IND}{IND}{IND}auto np = next_page_json(page.body, \"{}\")\n",
            self.output_token
        ));
        out.push_str(&format!("{IND}{IND}{IND}if not np.has_more:\n"));
        out.push_str(&format!("{IND}{IND}{IND}{IND}break\n"));
        out.push_str(&format!(
            "{IND}{IND}{IND}input.{} = {carry}\n",
            self.token_field
        ));
        out
    }
}

/// A flat botocore token field: a bare member name, not a nested JMESPath
/// expression (which contains `.` for sub-fields or `[` for list indexing). Only
/// flat fields are readable by the emitted `next_page_json` flat lookup.
fn is_flat_field(token: &str) -> bool {
    !token.is_empty() && !token.contains('.') && !token.contains('[')
}

/// Make `base` unique against `used` by appending `_`, `_2`, ... deterministically.
fn unique(base: &str, used: &[String]) -> String {
    if !used.iter().any(|u| u == base) {
        return base.to_string();
    }
    let mut cand = format!("{base}_");
    let mut n = 2;
    while used.contains(&cand) {
        cand = format!("{base}_{n}");
        n += 1;
    }
    cand
}

/// Does this member type block `@derive(Json)` (used only to name blockers)?
fn member_blocks_derive(model: &Model, ty: &ZapType, derivable: &HashMap<String, bool>) -> bool {
    match ty {
        ZapType::List(_) | ZapType::Dict(..) => true,
        ZapType::Struct(n) => !*derivable.get(n).unwrap_or(&false),
        _ => {
            let _ = model;
            false
        }
    }
}

fn json_wire_version(v: &str) -> &str {
    match v.trim() {
        "1.1" => "1.1",
        _ => "1.0",
    }
}

fn nonempty<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.is_empty() {
        b
    } else {
        a
    }
}

/// Lowercase-leading names -> PascalCase (fallback when there is no serviceId).
fn pascal(s: &str) -> String {
    let mut out = String::new();
    let mut up = true;
    for ch in s.chars() {
        if ch == '-' || ch == '_' || ch == ' ' {
            up = true;
            continue;
        }
        if up {
            out.extend(ch.to_uppercase());
            up = false;
        } else {
            out.push(ch);
        }
    }
    escape_ident(&out).0
}
