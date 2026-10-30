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

// --- #426: bool, nested collections, maps in a rest-xml document body --------
//
// A synthetic rest-xml model exercising every body shape #426 adds: a boolean
// (via the per-file `_xml_bool` helper), a nested structure, a WRAPPED list of
// structures (`<Items><Item>…`), a WRAPPED map (`<Tags><entry><key/><value/>`,
// keys sorted), and a FLATTENED list of structures (repeated `<Flat>…`). Proven
// end to end through the real generator + an independently reconstructed,
// SigV4-signed XML document body, like the earlier synthetic rest-xml coverage.

const XSYNTH: &str = r#"{
  "metadata":{"protocol":"rest-xml","endpointPrefix":"svc","serviceId":"XSynth","apiVersion":"2021-01-01"},
  "operations":{"PutThing":{"name":"PutThing","http":{"method":"PUT","requestUri":"/thing/{Id}"},"input":{"shape":"PutThingRequest"}}},
  "shapes":{
    "S":{"type":"string"},"B":{"type":"boolean"},
    "Owner":{"type":"structure","required":["Id"],"members":{"Id":{"shape":"S"}}},
    "Item":{"type":"structure","required":["Name"],"members":{"Name":{"shape":"S"}}},
    "ItemList":{"type":"list","member":{"shape":"Item","locationName":"Item"}},
    "Thing":{"type":"structure","required":["V"],"members":{"V":{"shape":"S"}}},
    "FlatThings":{"type":"list","member":{"shape":"Thing"},"flattened":true},
    "StrMap":{"type":"map","key":{"shape":"S"},"value":{"shape":"S"}},
    "Config":{"type":"structure","required":["Enabled","Owner","Items","Tags","Flat"],
      "xmlNamespace":{"uri":"urn:xsynth"},
      "members":{"Enabled":{"shape":"B"},"Owner":{"shape":"Owner"},"Items":{"shape":"ItemList"},
        "Tags":{"shape":"StrMap"},"Flat":{"shape":"FlatThings"}}},
    "PutThingRequest":{"type":"structure","required":["Id","Config"],
      "members":{"Id":{"shape":"S","location":"uri","locationName":"Id"},
        "Config":{"shape":"Config","locationName":"Config"}},"payload":"Config"}}}"#;

#[test]
fn generated_restxml_synthetic_collections_match_golden() {
    let src = generate_model(XSYNTH);
    let mb = method_body(&src, "def put_thing(self, PutThingRequest input) -> str:");

    // Boolean via the per-file helper.
    assert!(src.contains("def svc_xml_bool(bool b) -> str:"), "{src}");
    assert!(
        mb.contains(
            "restxml.rest_xml_scalar(root, \"Enabled\", svc_xml_bool(input.Config.Enabled))"
        ),
        "{mb}"
    );
    // Nested struct.
    assert!(
        mb.contains("auto n0 = restxml.rest_xml_struct(root, \"Owner\")"),
        "{mb}"
    );
    // Wrapped list of structs: <Items> wrapper, each item <Item>.
    assert!(
        mb.contains("auto n1 = restxml.rest_xml_struct(root, \"Items\")"),
        "{mb}"
    );
    assert!(mb.contains("for t2 in input.Config.Items:"), "{mb}");
    assert!(
        mb.contains("auto n3 = restxml.rest_xml_struct(n1, \"Item\")"),
        "{mb}"
    );
    // Wrapped map: <Tags><entry><key/><value/></entry>, keys sorted.
    assert!(
        mb.contains("auto n4 = restxml.rest_xml_struct(root, \"Tags\")"),
        "{mb}"
    );
    assert!(
        mb.contains("for t5 in sorted(input.Config.Tags.keys()):"),
        "{mb}"
    );
    assert!(
        mb.contains("auto n6 = restxml.rest_xml_struct(n4, \"entry\")"),
        "{mb}"
    );
    assert!(
        mb.contains("restxml.rest_xml_scalar(n6, \"key\", t5)"),
        "{mb}"
    );
    // Flattened list of structs: repeated <Flat>.
    assert!(
        mb.contains("auto n8 = restxml.rest_xml_struct(root, \"Flat\")"),
        "{mb}"
    );

    let body = "<Config xmlns=\"urn:xsynth\"><Enabled>true</Enabled>\
                <Owner><Id>o1</Id></Owner>\
                <Items><Item><Name>a</Name></Item><Item><Name>b</Name></Item></Items>\
                <Tags><entry><key>k1</key><value>v1</value></entry>\
                <entry><key>k2</key><value>v2</value></entry></Tags>\
                <Flat><V>f1</V></Flat><Flat><V>f2</V></Flat></Config>";
    let path = expand_path("/thing/{Id}", &[("Id", "t 1".to_string())]);
    let got = binding_sign("svc", &host("svc"), "PUT", &path, body, "application/xml");
    assert_eq!(got, read("tests/expected/restxml_synth_collections.http"));
}

// An *optional* structured httpPayload (zaplang-io/zap#427): the same collection
// payload as XSYNTH, but `Config` is not required. The emitter guards the whole
// body on `is_some()` and reads the members off the unwrapped `pv`; a present
// payload serializes byte-identically (so it reuses the collections golden), and
// an absent one signs the bare binding with no body.
const XOPT: &str = r#"{
  "metadata":{"protocol":"rest-xml","endpointPrefix":"svc","serviceId":"XSynth","apiVersion":"2021-01-01"},
  "operations":{"PutThing":{"name":"PutThing","http":{"method":"PUT","requestUri":"/thing/{Id}"},"input":{"shape":"PutThingRequest"}}},
  "shapes":{
    "S":{"type":"string"},"B":{"type":"boolean"},
    "Owner":{"type":"structure","required":["Id"],"members":{"Id":{"shape":"S"}}},
    "Item":{"type":"structure","required":["Name"],"members":{"Name":{"shape":"S"}}},
    "ItemList":{"type":"list","member":{"shape":"Item","locationName":"Item"}},
    "Thing":{"type":"structure","required":["V"],"members":{"V":{"shape":"S"}}},
    "FlatThings":{"type":"list","member":{"shape":"Thing"},"flattened":true},
    "StrMap":{"type":"map","key":{"shape":"S"},"value":{"shape":"S"}},
    "Config":{"type":"structure","required":["Enabled","Owner","Items","Tags","Flat"],
      "xmlNamespace":{"uri":"urn:xsynth"},
      "members":{"Enabled":{"shape":"B"},"Owner":{"shape":"Owner"},"Items":{"shape":"ItemList"},
        "Tags":{"shape":"StrMap"},"Flat":{"shape":"FlatThings"}}},
    "PutThingRequest":{"type":"structure","required":["Id"],
      "members":{"Id":{"shape":"S","location":"uri","locationName":"Id"},
        "Config":{"shape":"Config","locationName":"Config"}},"payload":"Config"}}}"#;

#[test]
fn generated_restxml_optional_payload_matches_golden() {
    let src = generate_model(XOPT);
    let mb = method_body(&src, "def put_thing(self, PutThingRequest input) -> str:");

    // The body build is guarded on the optional payload being present; the
    // member is unwrapped to `pv`, which the serializer reads from.
    assert!(mb.contains("if input.Config.is_some():"), "{mb}");
    assert!(mb.contains("auto pv = input.Config.unwrap()"), "{mb}");
    assert!(
        mb.contains("restxml.rest_xml_scalar(root, \"Enabled\", svc_xml_bool(pv.Enabled))"),
        "{mb}"
    );
    assert!(mb.contains("for t2 in pv.Items:"), "{mb}");
    assert!(mb.contains("for t5 in sorted(pv.Tags.keys()):"), "{mb}");
    // Present -> sign the document body; absent -> sign the bare binding.
    assert!(
        mb.contains(
            "return restxml.rest_xml_request(self.creds, bp, svc_service(), self.region, host)"
        ),
        "{mb}"
    );
    assert!(
        mb.contains(
            "return restxml.rest_xml_request(self.creds, b, svc_service(), self.region, host)"
        ),
        "{mb}"
    );

    // A present payload serializes to the identical bytes as the required-case
    // collections golden, so the signed request matches it exactly.
    let body = "<Config xmlns=\"urn:xsynth\"><Enabled>true</Enabled>\
                <Owner><Id>o1</Id></Owner>\
                <Items><Item><Name>a</Name></Item><Item><Name>b</Name></Item></Items>\
                <Tags><entry><key>k1</key><value>v1</value></entry>\
                <entry><key>k2</key><value>v2</value></entry></Tags>\
                <Flat><V>f1</V></Flat><Flat><V>f2</V></Flat></Config>";
    let path = expand_path("/thing/{Id}", &[("Id", "t 1".to_string())]);
    let got = binding_sign("svc", &host("svc"), "PUT", &path, body, "application/xml");
    assert_eq!(got, read("tests/expected/restxml_synth_collections.http"));
}

// Real-service call-sequence lock (no golden): Route53's implicit XML document
// body (no httpPayload) is rooted at the operation input ref's name + namespace
// and built from the top-level members.
#[test]
fn generated_route53_change_rrsets_implicit_document_body() {
    let src = generate_model(&read("models/route53/2013-04-01/service-2.json"));
    let mb = method_body(
        &src,
        "def change_resource_record_sets(self, ChangeResourceRecordSetsRequest input) -> str:",
    );
    assert!(
        mb.contains("auto root = restxml.rest_xml_root_ns(\"ChangeResourceRecordSetsRequest\", \"https://route53.amazonaws.com/doc/2013-04-01/\")"),
        "{mb}"
    );
    assert!(
        mb.contains("restxml.rest_xml_struct(root, \"ChangeBatch\")"),
        "{mb}"
    );
    assert!(mb.contains("restxml.rest_xml_document(b, body)"), "{mb}");
}
