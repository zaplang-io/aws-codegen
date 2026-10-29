//! aws-codegen — a model-driven generator that consumes a botocore
//! `service-2.json` and emits a Zap AWS SDK client.
//!
//! The generator targets the AWS wire protocols: **awsJson** (DynamoDB),
//! **rest-json** (Lambda), **rest-xml** (CloudFront) and **query**/**ec2**
//! (SimpleDB / EC2). They share the shape, enum and error-set emission and
//! differ only in request/response framing: awsJson POSTs the whole input shape
//! as one JSON object (`aws.awsjson`); rest-json/rest-xml place members at HTTP
//! locations via the `aws.binding` layer and dispatch a JSON or XML body
//! (`aws.restjson` / `aws.restxml`); query/ec2 POST the input as a flat
//! form-urlencoded body (`aws.query`). See the module docs and `README.md`.

pub mod binding;
pub mod emit;
pub mod model;
pub mod naming;
pub mod query;
pub mod types;
pub mod xml;

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
    if !matches!(
        proto,
        "json" | "rest-json" | "rest-xml" | "query" | "ec2" | ""
    ) {
        return Err(format!(
            "unsupported protocol `{proto}`; the generator emits awsJson (`json`), \
             rest-json (`rest-json`), rest-xml (`rest-xml`) and query/ec2 \
             (`query`, `ec2`)"
        ));
    }
    let paginators = match paginators_json {
        Some(p) => Paginators::from_json_str(p)?,
        None => Paginators::default(),
    };
    Ok(generate(&model, &paginators))
}
