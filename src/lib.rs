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
pub mod cborbody;
pub mod emit;
pub mod jsonbody;
pub mod model;
pub mod naming;
pub mod query;
pub mod types;
pub mod xml;

pub use emit::{generate, package_manifest, Coverage, AWS_CORE_DEP_PATH};
pub use model::{Model, Paginators, Waiters};

/// Parse a `service-2.json` string and generate the Zap client source.
///
/// No pagination or waiter metadata; equivalent to passing empty
/// `paginators-1.json` / `waiters-2.json`. Use
/// [`generate_from_json_with_paginators`] to emit paginators (zaplang-io/
/// zap#349) and [`generate_from_json_with_sidecars`] to also emit waiters
/// (zaplang-io/aws-codegen#22).
pub fn generate_from_json(json: &str) -> Result<(String, Coverage), String> {
    generate_from_json_with_sidecars(json, None, None)
}

/// Generate the Zap client from a `service-2.json`, optionally driving
/// paginators off the matching botocore `paginators-1.json` sidecar.
pub fn generate_from_json_with_paginators(
    json: &str,
    paginators_json: Option<&str>,
) -> Result<(String, Coverage), String> {
    generate_from_json_with_sidecars(json, paginators_json, None)
}

/// Generate the Zap client from a `service-2.json`, optionally driving waiters
/// off the matching botocore `waiters-2.json` sidecar (no pagination metadata).
pub fn generate_from_json_with_waiters(
    json: &str,
    waiters_json: Option<&str>,
) -> Result<(String, Coverage), String> {
    generate_from_json_with_sidecars(json, None, waiters_json)
}

/// Generate the Zap client from a `service-2.json`, optionally driving
/// paginators off `paginators-1.json` and waiters off `waiters-2.json` — the two
/// botocore sidecars that ship next to the model. Both are parsed and threaded in
/// independently (an absent sidecar emits no paginators / waiters).
pub fn generate_from_json_with_sidecars(
    json: &str,
    paginators_json: Option<&str>,
    waiters_json: Option<&str>,
) -> Result<(String, Coverage), String> {
    let model = Model::from_json_str(json)?;
    let proto = model.metadata.protocol.trim();
    if !matches!(
        proto,
        "json" | "rest-json" | "rest-xml" | "query" | "ec2" | "smithy-rpc-v2-cbor" | ""
    ) {
        return Err(format!(
            "unsupported protocol `{proto}`; the generator emits awsJson (`json`), \
             rest-json (`rest-json`), rest-xml (`rest-xml`), query/ec2 \
             (`query`, `ec2`) and smithy-rpc-v2-cbor"
        ));
    }
    let paginators = match paginators_json {
        Some(p) => Paginators::from_json_str(p)?,
        None => Paginators::default(),
    };
    let waiters = match waiters_json {
        Some(w) => Waiters::from_json_str(w)?,
        None => Waiters::default(),
    };
    Ok(generate(&model, &paginators, &waiters))
}
