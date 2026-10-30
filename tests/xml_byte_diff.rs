//! Byte-diff fidelity gate for the generated rest-xml client (#354).
//!
//! Proves the rest-xml emitter is faithful: two CloudFront operations — a body
//! with a default namespace, a nested structure and a wrapped list
//! (`CreateInvalidation`), and a two-scalar body
//! (`CreateCloudFrontOriginAccessIdentity`) — plus a synthetic op exercising the
//! traits no small real rest-xml service carries (a prefixed-namespace root, an
//! `xmlAttribute`, and a *flattened* list) serialize, on the wire, byte-
//! identically to the requests the hand-written `aws.binding` + `aws.restxml`
//! codec (zaplang-io/aws #352) produces.
//!
//! Same toolchain-free design as the sibling gates: the generator-OWNED pieces —
//! the method + URI template, the root element name/namespace, and the sequence
//! of `rest_xml_*` body calls — are asserted out of the freshly generated
//! source, and the SigV4 signature over the reconstructed XML body is computed
//! by the independent binding signer in `tests/common` (the binding-path
//! contract shared with rest-json). The result is compared to the checked-in
//! goldens, which `tools/verify_xml_requests.py` reproduces from scratch.

mod common;

use common::{binding_sign, expand_path, read, REGION};

const CF_NS: &str = "http://cloudfront.amazonaws.com/doc/2015-09-17/";

fn host(service: &str) -> String {
    format!("{service}.{REGION}.amazonaws.com")
}

fn generate_model(model: &str) -> String {
    aws_codegen::generate_from_json(model)
        .expect("model generates")
        .0
}

fn method_body<'a>(src: &'a str, def_sig: &'a str) -> &'a str {
    let m = src
        .find(def_sig)
        .unwrap_or_else(|| panic!("generated client defines `{def_sig}`"));
    let rest = &src[m..];
    let end = rest[1..]
        .find("\n    def ")
        .map(|e| e + 1)
        .unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn generated_cloudfront_create_invalidation_matches_golden() {
    let src = generate_model(&read("models/cloudfront/2015-09-17/service-2.json"));
    assert!(src.contains("def cloudfront_service() -> str:"));
    assert!(src.contains("    return \"cloudfront\""));

    let sig = "def create_invalidation(self, CreateInvalidationRequest input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("path_template=\"/2015-09-17/distribution/{DistributionId}/invalidation\""));
    assert!(mb.contains("labels[\"DistributionId\"] = input.DistributionId"));
    // The payload structure root carries the default namespace; the nested
    // Paths struct holds a Quantity scalar and a wrapped Items/Path list.
    assert!(mb.contains(&format!(
        "auto root = restxml.rest_xml_root_ns(\"InvalidationBatch\", \"{CF_NS}\")"
    )));
    assert!(mb.contains("restxml.rest_xml_struct(root, \"Paths\")"));
    // The qualified codec prefix pushes this past 88 cols, so the `str(...)`
    // value is hoisted into a fresh local first (emit_hoisted).
    assert!(mb.contains("auto t1 = str(input.InvalidationBatch.Paths.Quantity)"));
    assert!(mb.contains("restxml.rest_xml_scalar(n0, \"Quantity\", t1)"));
    assert!(mb.contains("restxml.rest_xml_wrapped_list(n0, \"Items\", \"Path\","));
    assert!(mb.contains("restxml.rest_xml_scalar(root, \"CallerReference\","));
    assert!(mb.contains("auto bp = restxml.rest_xml_document(b, body)"));
    assert!(mb.contains("rest_xml_request(self.creds, bp, cloudfront_service()"));

    let body = format!(
        "<InvalidationBatch xmlns=\"{CF_NS}\"><Paths><Quantity>2</Quantity>\
         <Items><Path>/img/a.png</Path><Path>/img/b.png</Path></Items></Paths>\
         <CallerReference>ref-2021</CallerReference></InvalidationBatch>"
    );
    let path = expand_path(
        "/2015-09-17/distribution/{DistributionId}/invalidation",
        &[("DistributionId", "EDFDVBD6EXAMPLE".to_string())],
    );
    let got = binding_sign(
        "cloudfront",
        &host("cloudfront"),
        "POST",
        &path,
        &body,
        "application/xml",
    );
    assert_eq!(
        got,
        read("tests/expected/cloudfront_create_invalidation.http")
    );
}

#[test]
fn generated_cloudfront_create_oai_matches_golden() {
    let src = generate_model(&read("models/cloudfront/2015-09-17/service-2.json"));
    let sig = "def create_cloud_front_origin_access_identity(self, \
               CreateCloudFrontOriginAccessIdentityRequest input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains(&format!(
        "auto root = restxml.rest_xml_root_ns(\"CloudFrontOriginAccessIdentityConfig\", \"{CF_NS}\")"
    )));
    assert!(mb.contains("restxml.rest_xml_scalar(root, \"CallerReference\","));
    assert!(mb.contains("restxml.rest_xml_scalar(root, \"Comment\","));

    let body = format!(
        "<CloudFrontOriginAccessIdentityConfig xmlns=\"{CF_NS}\">\
         <CallerReference>oai-2021</CallerReference><Comment>my identity</Comment>\
         </CloudFrontOriginAccessIdentityConfig>"
    );
    let got = binding_sign(
        "cloudfront",
        &host("cloudfront"),
        "POST",
        "/2015-09-17/origin-access-identity/cloudfront",
        &body,
        "application/xml",
    );
    assert_eq!(got, read("tests/expected/cloudfront_create_oai.http"));
}

// A synthetic rest-xml model exercising a prefixed-namespace root, an
// xmlAttribute and a flattened list — traits only S3/Route53 carry among real
// rest-xml services, so proven here through the real generator (the same
// synthetic-coverage posture as binding.rs's greedy-label / prefix-header tests).
const SYNTH: &str = r#"{
  "metadata":{"protocol":"rest-xml","endpointPrefix":"svc","serviceId":"Synth","apiVersion":"2021-01-01"},
  "operations":{"PutThing":{"name":"PutThing","http":{"method":"PUT","requestUri":"/thing/{Id}"},
    "input":{"shape":"PutThingRequest"}}},
  "shapes":{
    "S":{"type":"string"},
    "AliasList":{"type":"list","member":{"shape":"S"},"flattened":true},
    "Config":{"type":"structure","required":["Name"],"xmlNamespace":{"uri":"urn:svc","prefix":"ns"},
      "members":{
        "Version":{"shape":"S","xmlAttribute":true,"locationName":"Version"},
        "Name":{"shape":"S"},
        "Alias":{"shape":"AliasList"}}},
    "PutThingRequest":{"type":"structure","required":["Id","Config"],
      "members":{"Id":{"shape":"S","location":"uri","locationName":"Id"},
        "Config":{"shape":"Config","locationName":"Config"}},"payload":"Config"}}}"#;

#[test]
fn generated_synthetic_restxml_matches_golden() {
    let src = generate_model(SYNTH);
    let sig = "def put_thing(self, PutThingRequest input) -> str:";
    let mb = method_body(&src, sig);
    // A prefixed-namespace root, an xmlAttribute, and a flattened list.
    assert!(
        mb.contains("auto root = restxml.rest_xml_root_prefixed(\"Config\", \"ns\", \"urn:svc\")")
    );
    assert!(
        mb.contains("restxml.rest_xml_attribute(root, \"Version\", input.Config.Version.unwrap())")
    );
    assert!(mb.contains("restxml.rest_xml_scalar(root, \"Name\", input.Config.Name)"));
    assert!(mb
        .contains("restxml.rest_xml_flat_list(root, \"Alias\", input.Config.Alias.unwrap_or([]))"));

    let body = "<ns:Config xmlns:ns=\"urn:svc\" Version=\"2\"><Name>gadget</Name>\
                <Alias>a1</Alias><Alias>a2</Alias></ns:Config>";
    let path = expand_path("/thing/{Id}", &[("Id", "t 1".to_string())]);
    let got = binding_sign("svc", &host("svc"), "PUT", &path, body, "application/xml");
    assert_eq!(got, read("tests/expected/restxml_synth_put_thing.http"));
}
