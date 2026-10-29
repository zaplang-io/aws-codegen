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
