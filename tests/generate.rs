//! Integration tests: the generator is deterministic, the checked-in DynamoDB
//! (awsJson) and Lambda (rest-json) outputs are up to date, and the protocol
//! contracts + escaping hold.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_model(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

fn dynamodb_model() -> String {
    read_model("models/dynamodb/2012-08-10/service-2.json")
}

fn lambda_model() -> String {
    read_model("models/lambda/2015-03-31/service-2.json")
}

fn lambda_paginators() -> String {
    read_model("models/lambda/2015-03-31/paginators-1.json")
}

/// Generate the checked-in Lambda client (rest-json, model + paginators sidecar).
fn generate_lambda() -> (String, aws_codegen::Coverage) {
    aws_codegen::generate_from_json_with_paginators(&lambda_model(), Some(&lambda_paginators()))
        .unwrap()
}

fn dynamodb_paginators() -> String {
    let p = repo_root().join("models/dynamodb/2012-08-10/paginators-1.json");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

/// Generate the checked-in DynamoDB client (model + pinned paginators sidecar).
fn generate_dynamodb() -> (String, aws_codegen::Coverage) {
    aws_codegen::generate_from_json_with_paginators(&dynamodb_model(), Some(&dynamodb_paginators()))
        .unwrap()
}

#[test]
fn checked_in_dynamodb_output_is_current() {
    let (src, _cov) = generate_dynamodb();
    let checked = repo_root().join("generated/dynamodb/dynamodb.zap");
    let on_disk = std::fs::read_to_string(&checked)
        .unwrap_or_else(|e| panic!("reading {}: {e}", checked.display()));
    assert_eq!(
        src, on_disk,
        "generated/dynamodb/dynamodb.zap is stale — re-run: \
         cargo run -- models/dynamodb/2012-08-10/service-2.json -o generated/dynamodb/dynamodb.zap"
    );
}

#[test]
fn dynamodb_coverage_is_substantial() {
    let (_src, cov) = generate_dynamodb();
    // The pinned model (botocore 1.43.121): 58 ops, 272 structures, enums + the
    // error set. Bumping the pin (tools/sync-models.py) can move these; update
    // this exact count and keep the `>=` floors below as the real contract.
    assert_eq!(cov.operations_total, 58);
    assert!(
        cov.operations_methods >= 25,
        "methods: {}",
        cov.operations_methods
    );
    assert!(cov.structs_total >= 200, "structs: {}", cov.structs_total);
    assert!(
        cov.structs_derivable >= 100,
        "derivable: {}",
        cov.structs_derivable
    );
    assert!(cov.enums >= 30, "enums: {}", cov.enums);
    assert!(cov.error_variants >= 25, "errors: {}", cov.error_variants);
    // paginators-1.json lists 5 paginated ops; the 3 List* ops have derivable
    // string-token input, Query/Scan do not.
    assert_eq!(cov.paginators, 3, "paginators: {}", cov.paginators);
    assert_eq!(
        cov.paginators_skipped, 2,
        "paginators skipped: {}",
        cov.paginators_skipped
    );
}

#[test]
fn generation_is_deterministic() {
    let a = generate_dynamodb().0;
    let b = generate_dynamodb().0;
    assert_eq!(a, b);
}

#[test]
fn paginator_contract_shape() {
    let (src, _cov) = generate_dynamodb();
    // The three List* paginators are emitted as yield-based iterator methods on
    // the client, threading the model's output_token back into the input_token.
    assert!(src.contains("def paginate_list_tables(self, ListTablesInput input):"));
    assert!(src.contains("def paginate_list_backups(self, ListBackupsInput input):"));
    assert!(
        src.contains("def paginate_list_tags_of_resource(self, ListTagsOfResourceInput input):")
    );
    // ListTables threads LastEvaluatedTableName -> ExclusiveStartTableName and
    // stops when the output token is absent.
    assert!(src.contains("auto np = next_page_json(page.body, \"LastEvaluatedTableName\")"));
    assert!(src.contains("input.ExclusiveStartTableName = Optional.Some(np.token)"));
    assert!(src.contains("yield page"));
    assert!(src.contains("if not np.has_more:"));
    // Query/Scan are paginated in the model but their input is not derivable, so
    // they are documented as skipped rather than emitted wrong.
    assert!(!src.contains("def paginate_query("));
    assert!(!src.contains("def paginate_scan("));
    assert!(src.contains("Query (input not derivable"));
    assert!(src.contains("Scan (input not derivable"));
}

#[test]
fn awsjson_contract_shape() {
    let src = aws_codegen::generate_from_json(&dynamodb_model())
        .unwrap()
        .0;
    assert!(src.contains("def dynamodb_protocol() -> AwsJson:"));
    assert!(src.contains("awsjson_1_0(\"DynamoDB_20120810\", \"dynamodb\")"));
    assert!(src.contains("struct DynamoDBClient:"));
    assert!(src.contains("def dynamodb_client(Credentials creds, str region) -> DynamoDBClient:"));
    // A derivable op dispatches through the codec with a derived body.
    assert!(src.contains("def describe_table(self, DescribeTableInput input) -> str:"));
    assert!(src.contains(
        "return awsjson_request_now(dynamodb_protocol(), self.creds, self.region, \"DescribeTable\", body)"
    ));
    // A non-derivable input is documented, not silently emitted wrong.
    assert!(src.contains("no @derive(Json)"));
    assert!(src.contains("@json(open)"));
    // Error dispatch.
    assert!(src.contains("enum DynamoDBError:"));
    assert!(src.contains("def dynamodb_error_from_code(str code) -> DynamoDBError:"));
    assert!(src.contains("ResourceNotFoundException"));
}

#[test]
fn supported_protocols_accepted_unknown_rejected() {
    // The emitter now spans the awsJson, rest-json, rest-xml and query/ec2
    // protocols; all are accepted. A protocol it does not emit yet (e.g. the
    // RPCv2 CBOR protocol) is rejected with a clear message.
    for proto in ["json", "rest-json", "rest-xml", "query", "ec2"] {
        let m = format!(
            r#"{{"metadata":{{"protocol":"{proto}","apiVersion":"2021-01-01","endpointPrefix":"x"}},"operations":{{}},"shapes":{{}}}}"#
        );
        assert!(
            aws_codegen::generate_from_json(&m).is_ok(),
            "protocol {proto} should be accepted"
        );
    }
    let m = r#"{"metadata":{"protocol":"smithy-rpc-v2-cbor","endpointPrefix":"x"},"operations":{},"shapes":{}}"#;
    let err = aws_codegen::generate_from_json(m).unwrap_err();
    assert!(err.contains("smithy-rpc-v2-cbor"), "{err}");
    assert!(err.contains("unsupported protocol"), "{err}");
}

// --- Lambda (rest-json) ------------------------------------------------------

#[test]
fn checked_in_lambda_output_is_current() {
    let (src, _cov) = generate_lambda();
    let checked = repo_root().join("generated/lambda/lambda.zap");
    let on_disk = std::fs::read_to_string(&checked)
        .unwrap_or_else(|e| panic!("reading {}: {e}", checked.display()));
    assert_eq!(
        src, on_disk,
        "generated/lambda/lambda.zap is stale — re-run: \
         cargo run -- models/lambda/2015-03-31/service-2.json -o generated/lambda/lambda.zap"
    );
}

#[test]
fn lambda_coverage_is_substantial() {
    let (_src, cov) = generate_lambda();
    assert_eq!(cov.operations_total, 88);
    assert!(
        cov.operations_methods >= 60,
        "methods: {}",
        cov.operations_methods
    );
    assert!(
        cov.operations_skipped > 0,
        "some ops skip (non-derivable docs)"
    );
    assert!(cov.error_variants >= 25, "errors: {}", cov.error_variants);
    // paginators-1.json lists 16 paginated ops; those whose input is generated
    // and whose token is a string Marker thread through.
    assert!(cov.paginators >= 12, "paginators: {}", cov.paginators);
}

#[test]
fn rest_json_contract_shape() {
    let (src, _cov) = generate_lambda();
    // Protocol seam: a service-name function, not an AwsJson config.
    assert!(src.contains("# Protocol: rest-json (restJson1)"));
    assert!(src.contains("def lambda__service() -> str:"));
    assert!(src.contains("    return \"lambda\""));
    assert!(src.contains("struct LambdaClient:"));

    // A GET with a path label + query, no body (dispatches the bare binding).
    assert!(src.contains("def get_function(self, GetFunctionRequest input) -> str:"));
    assert!(src.contains("labels[\"FunctionName\"] = input.FunctionName"));
    assert!(src.contains("path_template=\"/2015-03-31/functions/{FunctionName}\""));

    // A raw httpPayload blob (Invoke) and a JSON document body (PutFunction-
    // Concurrency) are both emitted through the rest-json codec.
    assert!(src.contains("rest_json_raw_payload(b, str(input.Payload.unwrap_or(bytes()))"));
    assert!(src.contains("struct PutFunctionConcurrencyDocument:"));
    assert!(src.contains("rest_json_document(b, doc.to_json())"));

    // A string enum bound to a header/query is carried as its plain wire string.
    assert!(src.contains("# wire string of the InvocationType enum (header binding)"));

    // Error dispatch and a yield-based paginator threading the Marker token.
    assert!(src.contains("enum LambdaError:"));
    assert!(src.contains("def lambda__error_from_code(str code) -> LambdaError:"));
    assert!(src.contains("def paginate_list_functions(self, ListFunctionsRequest input):"));
    assert!(src.contains("auto np = next_page_json(page.body, \"NextMarker\")"));
    assert!(src.contains("input.Marker = Optional.Some(np.token)"));
}

#[test]
fn lambda_generation_is_deterministic() {
    assert_eq!(generate_lambda().0, generate_lambda().0);
}

#[test]
fn paginator_with_nested_output_token_is_skipped() {
    // A paginator whose output_token is a nested JMESPath path (not a flat field)
    // cannot be read by the emitted `next_page_json` flat lookup, so it must be
    // document-skipped rather than emitted as a paginator that never advances.
    // (Mirrors Kinesis DescribeStream's `StreamDescription.Shards[-1].ShardId`.)
    let model = r#"{
      "metadata":{"protocol":"json","jsonVersion":"1.0","targetPrefix":"T","endpointPrefix":"svc","serviceId":"Svc"},
      "operations":{"ListThings":{"name":"ListThings","input":{"shape":"ListThingsInput"},"output":{"shape":"ListThingsOutput"}}},
      "shapes":{
        "ListThingsInput":{"type":"structure","members":{"Marker":{"shape":"Str"}}},
        "ListThingsOutput":{"type":"structure","members":{"Things":{"shape":"Str"}}},
        "Str":{"type":"string"}
      }
    }"#;
    let paginators = r#"{"pagination":{"ListThings":{
        "input_token":"Marker","output_token":"Result.Items[-1].Id","result_key":"Things"}}}"#;
    let (src, cov) =
        aws_codegen::generate_from_json_with_paginators(model, Some(paginators)).unwrap();
    assert_eq!(
        cov.paginators, 0,
        "nested-path paginator should not generate"
    );
    assert_eq!(cov.paginators_skipped, 1);
    assert!(!src.contains("def paginate_list_things("), "{src}");
    assert!(
        src.contains("Result.Items[-1].Id is a nested path, not a flat field"),
        "{src}"
    );
}

#[test]
fn keyword_and_reserved_names_are_escaped() {
    // A model whose names collide with Zap keywords and reserved words.
    let m = r#"{
      "metadata":{"protocol":"json","jsonVersion":"1.0","targetPrefix":"T","endpointPrefix":"svc","serviceId":"Svc"},
      "operations":{"In":{"name":"In","input":{"shape":"InInput"}}},
      "shapes":{
        "InInput":{"type":"structure","required":["in"],"members":{
          "in":{"shape":"Str"},
          "match":{"shape":"Mode"}
        }},
        "Str":{"type":"string"},
        "Mode":{"type":"string","enum":["list","dict","OK"]}
      }
    }"#;
    let src = aws_codegen::generate_from_json(m).unwrap().0;
    // Keyword field names get a trailing underscore + a wire-name note.
    assert!(src.contains("str in_"), "{src}");
    assert!(src.contains("wire name \"in\""));
    // The enum name `Mode` is fine; its keyword values are escaped.
    assert!(src.contains("enum Mode:"));
    assert!(src.contains("    list_"));
    assert!(src.contains("    dict_"));
    assert!(src.contains("    OK"));
    assert!(src.contains("    Unknown(str value)"));
}

// --- CloudFront (rest-xml), SimpleDB (query), EC2 (ec2) ----------------------

/// Generate a checked-in client from its pinned model + paginators sidecar
/// (exactly what `cargo run` / the CI determinism loop does).
fn generate_with_sidecar(service: &str, api_version: &str) -> (String, aws_codegen::Coverage) {
    let model = read_model(&format!("models/{service}/{api_version}/service-2.json"));
    let pag = read_model(&format!("models/{service}/{api_version}/paginators-1.json"));
    aws_codegen::generate_from_json_with_paginators(&model, Some(&pag)).unwrap()
}

fn assert_current(service: &str, api_version: &str, out_rel: &str) {
    let (src, _cov) = generate_with_sidecar(service, api_version);
    let checked = repo_root().join(out_rel);
    let on_disk = std::fs::read_to_string(&checked)
        .unwrap_or_else(|e| panic!("reading {}: {e}", checked.display()));
    assert_eq!(
        src, on_disk,
        "{out_rel} is stale — re-run: cargo run -- models/{service}/{api_version}/service-2.json -o {out_rel}"
    );
}

#[test]
fn checked_in_cloudfront_output_is_current() {
    assert_current(
        "cloudfront",
        "2015-09-17",
        "generated/cloudfront/cloudfront.zap",
    );
}

#[test]
fn checked_in_sdb_output_is_current() {
    assert_current("sdb", "2009-04-15", "generated/sdb/sdb.zap");
}

#[test]
fn checked_in_ec2_output_is_current() {
    assert_current("ec2", "2014-09-01", "generated/ec2/ec2.zap");
}

#[test]
fn restxml_contract_shape() {
    let (src, cov) = generate_with_sidecar("cloudfront", "2015-09-17");
    assert_eq!(cov.operations_total, 22);
    assert!(
        cov.operations_methods >= 15,
        "methods: {}",
        cov.operations_methods
    );
    assert!(cov.operations_skipped > 0, "complex payloads skip");
    // Protocol seam: a service-name function, plain structs (no @derive(Json)).
    assert!(src.contains("# Protocol: rest-xml"));
    assert!(src.contains("def cloudfront_service() -> str:"));
    assert!(src.contains("    return \"cloudfront\""));
    assert!(
        !src.contains("@derive(Json)\nstruct"),
        "rest-xml structs are plain carriers"
    );
    // A namespaced XML document body with a nested struct + wrapped list.
    assert!(src.contains("rest_xml_root_ns(\"InvalidationBatch\","));
    assert!(src.contains("rest_xml_struct(root, \"Paths\")"));
    assert!(src.contains("rest_xml_wrapped_list(n0, \"Items\", \"Path\","));
    assert!(src.contains("rest_xml_document(b, body)"));
    // Error dispatch from the rest-xml <Error><Code>.
    assert!(src.contains("enum CloudFrontError:"));
    assert!(src.contains("def cloudfront_error_from_code(str code) -> CloudFrontError:"));
    // A GET with only a path label sends no XML body (bare binding).
    assert!(src.contains("def get_distribution(self, GetDistributionRequest input) -> str:"));
}

#[test]
fn query_contract_shape() {
    let (src, cov) = generate_with_sidecar("sdb", "2009-04-15");
    assert_eq!(cov.operations_total, 10);
    assert!(
        cov.operations_methods >= 5,
        "methods: {}",
        cov.operations_methods
    );
    assert!(src.contains("# Protocol: query"));
    assert!(src.contains("def sdb_service() -> str:"));
    assert!(src.contains("    return \"sdb\""));
    assert!(src.contains("auto p = query_params(\"GetAttributes\", \"2009-04-15\")"));
    assert!(src.contains("query_flat_list(p, \"AttributeNames\","));
    assert!(src.contains("query_bool(input.ConsistentRead.unwrap())"));
    assert!(src.contains("return query_request(self.creds, sdb_service(), self.region, p)"));
}

#[test]
fn ec2_contract_shape() {
    let (src, cov) = generate_with_sidecar("ec2", "2014-09-01");
    assert_eq!(cov.operations_total, 154);
    assert!(
        cov.operations_methods >= 80,
        "methods: {}",
        cov.operations_methods
    );
    assert!(src.contains("# Protocol: ec2"));
    assert!(src.contains("def ec2_service() -> str:"));
    assert!(src.contains("    return \"ec2\""));
    assert!(src.contains("auto p = query_params(\"MonitorInstances\", \"2014-09-01\")"));
    // ec2 capitalizes the key and always flattens the list.
    assert!(src.contains("query_flat_list(p, \"InstanceId\", input.InstanceIds)"));
    assert!(src.contains("query_scalar(p, \"DryRun\","));
}

#[test]
fn xml_family_generation_is_deterministic() {
    assert_eq!(
        generate_with_sidecar("cloudfront", "2015-09-17").0,
        generate_with_sidecar("cloudfront", "2015-09-17").0
    );
    assert_eq!(
        generate_with_sidecar("ec2", "2014-09-01").0,
        generate_with_sidecar("ec2", "2014-09-01").0
    );
}
