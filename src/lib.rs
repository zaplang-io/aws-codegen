//! aws-codegen — a model-driven generator that consumes a botocore
//! `service-2.json` and emits a Zap AWS SDK client.
//!
//! v0 targets the **awsJson** protocol (DynamoDB is the proof), emitting shapes
//! as `@derive(Json)` structs, string enums as `@json(open)` enums, a service
//! error enum + classifier, and a client that dispatches through the
//! `aws.awsjson` codec. See the module docs and `README.md` for the design.

pub mod emit;
pub mod model;
pub mod naming;
pub mod types;

pub use emit::{generate, Coverage};
pub use model::Model;

/// Parse a `service-2.json` string and generate the Zap client source.
pub fn generate_from_json(json: &str) -> Result<(String, Coverage), String> {
    let model = Model::from_json_str(json)?;
    let proto = model.metadata.protocol.trim();
    if !(proto == "json" || proto.is_empty()) {
        return Err(format!(
            "v0 supports the awsJson protocol only; model protocol is `{proto}` \
             (rest-json/xml/query are later tickets)"
        ));
    }
    Ok(generate(&model))
}
