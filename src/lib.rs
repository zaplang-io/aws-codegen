//! aws-codegen — a model-driven generator that consumes a botocore
//! `service-2.json` and emits a Zap AWS SDK client.
//!
//! The generator targets two protocols: **awsJson** (DynamoDB is the proof) and
//! **rest-json** (Lambda is the proof). Both emit shapes as `@derive(Json)`
//! structs, string enums as `@json(open)` enums, and a service error enum +
//! classifier; they differ only in request/response framing. awsJson POSTs the
//! whole input shape as one JSON object through the `aws.awsjson` codec;
//! rest-json places members at HTTP locations (path/query/header/payload) via
//! the `aws.binding` layer and dispatches through the `aws.restjson` codec. See
//! the module docs and `README.md` for the design.

pub mod binding;
pub mod emit;
pub mod model;
pub mod naming;
pub mod types;

pub use emit::{generate, Coverage};
pub use model::{Model, Paginators};

/// Parse a `service-2.json` string and generate the Zap client source.
///
/// No pagination metadata; equivalent to passing an empty `paginators-1.json`.
/// Use [`generate_from_json_with_paginators`] to emit paginators (zaplang-io/
/// zap#349).
pub fn generate_from_json(json: &str) -> Result<(String, Coverage), String> {
    generate_from_json_with_paginators(json, None)
}

/// Generate the Zap client from a `service-2.json`, optionally driving
/// paginators off the matching botocore `paginators-1.json` sidecar.
pub fn generate_from_json_with_paginators(
    json: &str,
    paginators_json: Option<&str>,
) -> Result<(String, Coverage), String> {
    let model = Model::from_json_str(json)?;
    let proto = model.metadata.protocol.trim();
    if !(proto == "json" || proto == "rest-json" || proto.is_empty()) {
        return Err(format!(
            "unsupported protocol `{proto}`; the generator emits awsJson (`json`) \
             and rest-json (`rest-json`) — rest-xml/query are later tickets \
             (zaplang-io/aws-codegen#352/#353)"
        ));
    }
    let paginators = match paginators_json {
        Some(p) => Paginators::from_json_str(p)?,
        None => Paginators::default(),
    };
    Ok(generate(&model, &paginators))
}
