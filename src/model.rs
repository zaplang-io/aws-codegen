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
    /// The service-level default XML namespace (e.g. ec2's
    /// `http://ec2.amazonaws.com/doc/<version>`). Informational for the XML
    /// protocols; the per-member/per-shape `xmlNamespace` is what the emitter
    /// serializes on the wire.
    #[serde(rename = "xmlNamespace", default)]
    pub xml_namespace: Option<XmlNamespace>,
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

/// An XML namespace trait (`xmlNamespace`). botocore writes it either as a bare
/// URI string (service-level `metadata.xmlNamespace`) or as an object
/// `{"uri": "...", "prefix": "..."}` (member/shape level); both normalize here.
/// A `prefix` makes the declaration `xmlns:prefix="uri"` and the element tag
/// `prefix:name`; without one it is a default `xmlns="uri"`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "XmlNamespaceRaw")]
pub struct XmlNamespace {
    pub uri: String,
    pub prefix: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum XmlNamespaceRaw {
    Uri(String),
    Obj {
        #[serde(default)]
        uri: String,
        #[serde(default)]
        prefix: Option<String>,
    },
}

impl From<XmlNamespaceRaw> for XmlNamespace {
    fn from(raw: XmlNamespaceRaw) -> Self {
        match raw {
            XmlNamespaceRaw::Uri(uri) => XmlNamespace { uri, prefix: None },
            XmlNamespaceRaw::Obj { uri, prefix } => XmlNamespace { uri, prefix },
        }
    }
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
    /// `xmlName`: overrides the on-the-wire element/key name for XML protocols
    /// (rest-xml element tag, awsQuery/ec2 member name) when it differs from the
    /// member name. botocore folds this into `locationName`, but a handful of
    /// shapes carry a distinct `xmlName`, so it is read explicitly.
    #[serde(rename = "xmlName", default)]
    pub xml_name: Option<String>,
    /// `xmlNamespace`: an XML namespace declared on this member's element.
    #[serde(rename = "xmlNamespace", default)]
    pub xml_namespace: Option<XmlNamespace>,
    /// `xmlAttribute`: this (scalar) member is serialized as an XML attribute of
    /// its parent element rather than a child element (rest-xml).
    #[serde(rename = "xmlAttribute", default)]
    pub xml_attribute: bool,
    /// `flattened` on a member ref (some models mark the list/map member rather
    /// than its shape): the list/map is serialized without a wrapper element.
    #[serde(default)]
    pub flattened: bool,
    /// `queryName` (the Smithy `ec2QueryName`): the verbatim ec2-protocol key for
    /// this member, used ahead of the capitalized `locationName`.
    #[serde(rename = "queryName", default)]
    pub query_name: Option<String>,
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
    /// `flattened` on a list/map shape: serialized without a wrapper element
    /// (rest-xml `<name>v</name><name>v</name>`) or without the `.member`/
    /// `.entry` path segment (awsQuery `name.N`).
    #[serde(default)]
    pub flattened: bool,
    /// `xmlName` on the shape: the default element/key name for the shape.
    #[serde(rename = "xmlName", default)]
    pub xml_name: Option<String>,
    /// `xmlNamespace` declared on the shape itself (rest-xml).
    #[serde(rename = "xmlNamespace", default)]
    pub xml_namespace: Option<XmlNamespace>,
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

/// The botocore `waiters-2.json` sidecar: poll-until-state waiter definitions
/// keyed by waiter name (e.g. `TableExists`). Botocore ships it as its own file
/// next to `service-2.json`, so — like [`Paginators`] — it is parsed and threaded
/// in independently. The shape mirrors `aws_core.waiters`' `WaiterConfig`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Waiters {
    #[serde(default)]
    pub waiters: IndexMap<String, Waiter>,
}

/// One waiter definition: which `operation` to poll, the `delay` (seconds)
/// between polls and the `max_attempts` poll cap, and the ordered `acceptors`
/// that decide success/failure/retry from each response.
#[derive(Debug, Clone, Deserialize)]
pub struct Waiter {
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub delay: i64,
    #[serde(rename = "maxAttempts", default)]
    pub max_attempts: i64,
    #[serde(default)]
    pub acceptors: Vec<Acceptor>,
}

/// One acceptor: the `state` transition to take when `matcher` matches a
/// response. `argument` is the JMESPath for the `path`/`pathAll`/`pathAny`
/// matchers (absent for `status`/`error`); `expected` is the comparison value,
/// normalized to the string the engine compares against ("200", "ACTIVE", …).
#[derive(Debug, Clone, Deserialize)]
pub struct Acceptor {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub matcher: String,
    #[serde(default)]
    pub argument: Option<String>,
    #[serde(default)]
    pub expected: Expected,
}

/// An acceptor's `expected` value. botocore writes it as a string ("ACTIVE"), an
/// integer (an HTTP status code, `200`) or a bool (`true`, for a boolean path
/// match); all three normalize to the string the waiter engine compares a
/// response against (`str(resp.status)`, an enum value, `"true"`/`"false"`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expected(pub String);

impl<'de> Deserialize<'de> for Expected {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = serde_json::Value::deserialize(d)?;
        let s = match v {
            serde_json::Value::String(s) => s,
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Null => String::new(),
            other => other.to_string(),
        };
        Ok(Expected(s))
    }
}

impl Waiters {
    /// Parse `waiters-2.json`.
    pub fn from_json_str(s: &str) -> Result<Waiters, String> {
        serde_json::from_str(s).map_err(|e| format!("parsing waiters-2.json: {e}"))
    }

    /// Waiter names, sorted for deterministic iteration.
    pub fn sorted_waiter_names(&self) -> Vec<&String> {
        let mut v: Vec<&String> = self.waiters.keys().collect();
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

    /// The XML/query element or key name for a member: `locationName`, else
    /// `xmlName`, else the member name. (botocore folds `xmlName` into the
    /// serialization `name`; this mirrors that precedence.)
    pub fn xml_wire_name<'a>(&'a self, member: &'a str) -> &'a str {
        self.location_name
            .as_deref()
            .or(self.xml_name.as_deref())
            .unwrap_or(member)
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

    pub fn is_list(&self) -> bool {
        self.kind == "list"
    }

    pub fn is_map(&self) -> bool {
        self.kind == "map"
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

    #[test]
    fn waiters_parse_operation_delay_and_acceptors() {
        // A DynamoDB-shaped table: two waiters on DescribeTable, with path/error
        // acceptors and a string `expected`.
        let w = Waiters::from_json_str(
            r#"{"version":2,"waiters":{
                 "TableExists":{"delay":20,"operation":"DescribeTable","maxAttempts":25,
                   "acceptors":[
                     {"expected":"ACTIVE","matcher":"path","state":"success","argument":"Table.TableStatus"},
                     {"expected":"ResourceNotFoundException","matcher":"error","state":"retry"}]},
                 "TableNotExists":{"delay":20,"operation":"DescribeTable","maxAttempts":25,
                   "acceptors":[
                     {"expected":"ResourceNotFoundException","matcher":"error","state":"success"}]}
               }}"#,
        )
        .unwrap();

        let te = &w.waiters["TableExists"];
        assert_eq!(te.operation, "DescribeTable");
        assert_eq!(te.delay, 20);
        assert_eq!(te.max_attempts, 25);
        assert_eq!(te.acceptors.len(), 2);
        assert_eq!(te.acceptors[0].matcher, "path");
        assert_eq!(te.acceptors[0].state, "success");
        assert_eq!(
            te.acceptors[0].argument.as_deref(),
            Some("Table.TableStatus")
        );
        assert_eq!(te.acceptors[0].expected, Expected("ACTIVE".to_string()));
        // An error matcher carries no JMESPath argument.
        assert_eq!(te.acceptors[1].matcher, "error");
        assert_eq!(te.acceptors[1].argument, None);

        // Deterministic ordering of waiter names.
        assert_eq!(
            w.sorted_waiter_names(),
            vec!["TableExists", "TableNotExists"]
        );
    }

    #[test]
    fn waiters_normalize_non_string_expected() {
        // S3 BucketExists uses integer status codes; botocore also writes boolean
        // path matches. Both normalize to the string the engine compares.
        let w = Waiters::from_json_str(
            r#"{"version":2,"waiters":{
                 "BucketExists":{"delay":5,"operation":"HeadBucket","maxAttempts":20,
                   "acceptors":[
                     {"expected":200,"matcher":"status","state":"success"},
                     {"expected":404,"matcher":"status","state":"retry"}]},
                 "FlagSet":{"delay":1,"operation":"Describe","maxAttempts":2,
                   "acceptors":[
                     {"expected":true,"matcher":"path","state":"success","argument":"Enabled"}]}
               }}"#,
        )
        .unwrap();

        let be = &w.waiters["BucketExists"];
        assert_eq!(be.acceptors[0].expected, Expected("200".to_string()));
        assert_eq!(be.acceptors[0].matcher, "status");
        assert_eq!(be.acceptors[1].expected, Expected("404".to_string()));

        let fs = &w.waiters["FlagSet"];
        assert_eq!(fs.acceptors[0].expected, Expected("true".to_string()));
    }

    #[test]
    fn absent_waiters_is_empty() {
        let w = Waiters::default();
        assert!(w.waiters.is_empty());
        assert!(w.sorted_waiter_names().is_empty());
    }
}
