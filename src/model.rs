//! Botocore `service-2.json` model: the subset of the schema the v0 generator
//! consumes, deserialized with `serde`. Member insertion order is preserved
//! (via `IndexMap`) because it is the order AWS documents the shape in and the
//! order we emit struct fields; everything else is iterated in sorted order for
//! deterministic output.

use indexmap::IndexMap;
use serde::Deserialize;

/// A parsed botocore service model.
#[derive(Debug, Clone, Deserialize)]
pub struct Model {
    pub metadata: Metadata,
    #[serde(default)]
    pub operations: IndexMap<String, Operation>,
    #[serde(default)]
    pub shapes: IndexMap<String, Shape>,
}

/// Service-level metadata (the `metadata` object).
#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    #[serde(default)]
    pub protocol: String,
    #[serde(rename = "jsonVersion", default)]
    pub json_version: String,
    #[serde(rename = "targetPrefix", default)]
    pub target_prefix: String,
    #[serde(rename = "apiVersion", default)]
    pub api_version: String,
    #[serde(rename = "endpointPrefix", default)]
    pub endpoint_prefix: String,
    /// The SigV4 signing name, when it differs from `endpointPrefix` (rare).
    /// Used as the rest-json SigV4 service name; falls back to `endpointPrefix`.
    #[serde(rename = "signingName", default)]
    pub signing_name: String,
    #[serde(rename = "serviceId", default)]
    pub service_id: String,
    #[serde(rename = "serviceFullName", default)]
    pub service_full_name: String,
    #[serde(rename = "signatureVersion", default)]
    pub signature_version: String,
}

/// An operation (`operations.<Name>`).
#[derive(Debug, Clone, Deserialize)]
pub struct Operation {
    pub name: String,
    #[serde(default)]
    pub http: Option<Http>,
    #[serde(default)]
    pub input: Option<ShapeRef>,
    #[serde(default)]
    pub output: Option<ShapeRef>,
    #[serde(default)]
    pub errors: Vec<ShapeRef>,
}

/// The `http` trait on an operation.
#[derive(Debug, Clone, Deserialize)]
pub struct Http {
    #[serde(default)]
    pub method: String,
    #[serde(rename = "requestUri", default)]
    pub request_uri: String,
}

/// A reference to a shape, optionally carrying member-level traits.
#[derive(Debug, Clone, Deserialize)]
pub struct ShapeRef {
    pub shape: String,
    #[serde(rename = "timestampFormat", default)]
    pub timestamp_format: Option<String>,
    /// The Smithy HTTP binding location of this member (rest-json et al.):
    /// `"uri"` (httpLabel), `"querystring"` (httpQuery), `"header"`
    /// (httpHeader), `"headers"` (httpPrefixHeaders), `"statusCode"`
    /// (httpResponseCode). Absent for an unbound (document-body) member.
    #[serde(default)]
    pub location: Option<String>,
    /// The wire name for a bound member — the path label name, query parameter,
    /// header name, or header prefix (defaults to the member name when absent).
    #[serde(rename = "locationName", default)]
    pub location_name: Option<String>,
}

/// A shape definition (`shapes.<Name>`).
#[derive(Debug, Clone, Deserialize)]
pub struct Shape {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub members: IndexMap<String, ShapeRef>,
    #[serde(default)]
    pub required: Vec<String>,
    /// `list` element.
    #[serde(default)]
    pub member: Option<ShapeRef>,
    /// `map` key.
    #[serde(default)]
    pub key: Option<ShapeRef>,
    /// `map` value.
    #[serde(default)]
    pub value: Option<ShapeRef>,
    /// `string` enum values.
    #[serde(rename = "enum", default)]
    pub enum_values: Option<Vec<String>>,
    /// Shape-level `timestampFormat`.
    #[serde(rename = "timestampFormat", default)]
    pub timestamp_format: Option<String>,
    /// The `httpPayload` member of a request/response structure (rest-json):
    /// the single member carried as the raw body, if any.
    #[serde(default)]
    pub payload: Option<String>,
}

/// The botocore `paginators-1.json` sidecar: pagination metadata keyed by
/// operation name. Separate from `service-2.json` (botocore ships it as its own
/// file), so it is parsed and threaded in independently.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Paginators {
    #[serde(default)]
    pub pagination: IndexMap<String, Paginator>,
}

/// One operation's pagination config. `input_token`/`output_token`/`result_key`
/// are a single name for simple listings but a parallel list for a few ops (so
/// they are modeled as [`StringOrList`]); `limit_key` is the per-page cap field.
#[derive(Debug, Clone, Deserialize)]
pub struct Paginator {
    #[serde(rename = "input_token", default)]
    pub input_token: StringOrList,
    #[serde(rename = "output_token", default)]
    pub output_token: StringOrList,
    #[serde(rename = "limit_key", default)]
    pub limit_key: Option<String>,
    #[serde(rename = "result_key", default)]
    pub result_key: StringOrList,
}

/// A paginators field that botocore writes as either a bare string or a list of
/// strings. Normalized to a `Vec` so callers treat both uniformly; an absent
/// field deserializes to the empty vec.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(from = "StringOrListRaw")]
pub struct StringOrList(pub Vec<String>);

#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrListRaw {
    One(String),
    Many(Vec<String>),
}

impl From<StringOrListRaw> for StringOrList {
    fn from(raw: StringOrListRaw) -> Self {
        match raw {
            StringOrListRaw::One(s) => StringOrList(vec![s]),
            StringOrListRaw::Many(v) => StringOrList(v),
        }
    }
}

impl StringOrList {
    /// The single value, when the field carries exactly one name.
    pub fn single(&self) -> Option<&str> {
        match self.0.as_slice() {
            [one] => Some(one.as_str()),
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Paginators {
    /// Parse `paginators-1.json`.
    pub fn from_json_str(s: &str) -> Result<Paginators, String> {
        serde_json::from_str(s).map_err(|e| format!("parsing paginators-1.json: {e}"))
    }

    /// Paginated operation names, sorted for deterministic iteration.
    pub fn sorted_operation_names(&self) -> Vec<&String> {
        let mut v: Vec<&String> = self.pagination.keys().collect();
        v.sort();
        v
    }
}

impl Model {
    /// Parse a model from the raw `service-2.json` text.
    pub fn from_json_str(s: &str) -> Result<Model, String> {
        serde_json::from_str(s).map_err(|e| format!("parsing service-2.json: {e}"))
    }

    /// Look up a shape by name.
    pub fn shape(&self, name: &str) -> Option<&Shape> {
        self.shapes.get(name)
    }

    /// Shape names sorted for deterministic iteration.
    pub fn sorted_shape_names(&self) -> Vec<&String> {
        let mut v: Vec<&String> = self.shapes.keys().collect();
        v.sort();
        v
    }

    /// Operation names sorted for deterministic iteration.
    pub fn sorted_operation_names(&self) -> Vec<&String> {
        let mut v: Vec<&String> = self.operations.keys().collect();
        v.sort();
        v
    }
}

impl ShapeRef {
    /// The wire name of a bound member: the `locationName` trait when present,
    /// else the member name itself.
    pub fn wire_name<'a>(&'a self, member: &'a str) -> &'a str {
        self.location_name.as_deref().unwrap_or(member)
    }
}

impl Http {
    /// Whether the request URI template binds `name` as a greedy label
    /// (`{name+}`, which spans path segments and keeps `/`).
    pub fn label_is_greedy(&self, name: &str) -> bool {
        self.request_uri.contains(&format!("{{{name}+}}"))
    }
}

impl Shape {
    pub fn is_structure(&self) -> bool {
        self.kind == "structure"
    }

    /// A `string` shape with at least two enumerated values (the floor for an
    /// `@json(open)` enum — a single-value enum degrades to `str`).
    pub fn is_enum(&self) -> bool {
        self.kind == "string"
            && self
                .enum_values
                .as_ref()
                .map(|v| v.len() >= 2)
                .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paginators_accept_string_or_list_tokens() {
        // botocore writes tokens as a bare string (ListTables) or a parallel list
        // (result_key on Query/Scan); both normalize to a Vec.
        let p = Paginators::from_json_str(
            r#"{"pagination":{
                 "ListTables":{"input_token":"ExclusiveStartTableName",
                               "output_token":"LastEvaluatedTableName",
                               "limit_key":"Limit","result_key":"TableNames"},
                 "Scan":{"input_token":"ExclusiveStartKey",
                         "output_token":"LastEvaluatedKey",
                         "result_key":["Items","Count"]}
               }}"#,
        )
        .unwrap();

        let lt = &p.pagination["ListTables"];
        assert_eq!(lt.input_token.single(), Some("ExclusiveStartTableName"));
        assert_eq!(lt.output_token.single(), Some("LastEvaluatedTableName"));
        assert_eq!(lt.limit_key.as_deref(), Some("Limit"));
        assert_eq!(lt.result_key.0, vec!["TableNames".to_string()]);

        let scan = &p.pagination["Scan"];
        // A multi-field result_key has no single value.
        assert_eq!(scan.result_key.single(), None);
        assert_eq!(
            scan.result_key.0,
            vec!["Items".to_string(), "Count".to_string()]
        );
        // Deterministic ordering of paginated op names.
        assert_eq!(p.sorted_operation_names(), vec!["ListTables", "Scan"]);
    }

    #[test]
    fn absent_paginators_is_empty() {
        let p = Paginators::default();
        assert!(p.pagination.is_empty());
        assert!(p.sorted_operation_names().is_empty());
    }
}
