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

fn cloudwatch_model() -> String {
    read_model("models/cloudwatch/2010-08-01/service-2.json")
}

fn translate_model() -> String {
    read_model("models/translate/2017-07-01/service-2.json")
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
    let checked = repo_root().join("generated/dynamodb/src/dynamodb.zap");
    let on_disk = std::fs::read_to_string(&checked)
        .unwrap_or_else(|e| panic!("reading {}: {e}", checked.display()));
    assert_eq!(
        src, on_disk,
        "generated/dynamodb/src/dynamodb.zap is stale — re-run: \
         cargo run -- models/dynamodb/2012-08-10/service-2.json --package generated/dynamodb --name dynamodb"
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
    assert!(src.contains("auto np = core.next_page_json(page.body, \"LastEvaluatedTableName\")"));
    assert!(src.contains("input.ExclusiveStartTableName = Optional.Some(np.token)"));
    assert!(src.contains("yield page"));
    assert!(src.contains("if not np.has_more:"));
    // Query/Scan now serialize their AttributeValue-map input via explicit
    // serializers (zaplang-io/zap#424), so the operations themselves generate;
    // but their paginator token `ExclusiveStartKey` is a map, not a string
    // field, so the paginator is still documented as skipped (never emitted).
    assert!(src.contains("def query(self, QueryInput input) -> str:"));
    assert!(src.contains("def scan(self, ScanInput input) -> str:"));
    assert!(!src.contains("def paginate_query("));
    assert!(!src.contains("def paginate_scan("));
    assert!(src.contains("Query (input_token ExclusiveStartKey is not a string field)"));
    assert!(src.contains("Scan (input_token ExclusiveStartKey is not a string field)"));
}

#[test]
fn awsjson_contract_shape() {
    let src = aws_codegen::generate_from_json(&dynamodb_model())
        .unwrap()
        .0;
    assert!(src.contains("def dynamodb_protocol() -> awsjson.AwsJson:"));
    assert!(src.contains("awsjson.awsjson_1_0(\"DynamoDB_20120810\", \"dynamodb\")"));
    assert!(src.contains("struct DynamoDBClient:"));
    assert!(
        src.contains("def dynamodb_client(core.Credentials creds, str region) -> DynamoDBClient:")
    );
    // A derivable op dispatches through the codec with a derived body.
    assert!(src.contains("def describe_table(self, DescribeTableInput input) -> str:"));
    assert!(src.contains(
        "return awsjson.awsjson_request_now(dynamodb_protocol(), self.creds, self.region, \"DescribeTable\", body)"
    ));
    // A non-derivable input is documented, not silently emitted wrong.
    assert!(src.contains("no @derive(Json)"));
    assert!(src.contains("@json(open)"));
    // Error dispatch.
    assert!(src.contains("enum DynamoDBError:"));
    assert!(src.contains("def dynamodb_error_from_code(str code) -> DynamoDBError:"));
    assert!(src.contains("ResourceNotFoundException"));
}

// --- smithy-rpc-v2-cbor (CloudWatch / Translate) -----------------------------

#[test]
fn cbor_contract_shape() {
    // Translate is a clean cbor service (no non-text-keyed maps): every operation
    // gets a method that builds a CBOR body and signs over the bytes.
    let src = aws_codegen::generate_from_json(&translate_model())
        .unwrap()
        .0;
    // The protocol helper returns the SigV4 service name (also the host prefix).
    assert!(src.contains("def translate_service() -> str:"));
    // A cbor method returns `bytes` (binary wire form) and dispatches through the
    // aws_core cbor codec to /service/<targetPrefix>/operation/<Op>.
    assert!(src.contains("def translate_text(self, TranslateTextRequest input) -> bytes:"));
    assert!(src.contains("auto body = cbor.cbor_encode(translate_text_request_to_cbor(input))"));
    assert!(src.contains(
        "cbor.cbor_build_request(translate_service(), self.region, host, \"AWSShineFrontendService_20170701\", \"TranslateText\", body, t.amz_date)"
    ));
    assert!(src.contains("return cbor.cbor_sign(self.creds, req, body, t.amz_date, t.date_stamp)"));
    // The body serializer builds a cbor.CborValue map in model order.
    assert!(src
        .contains("def translate_text_request_to_cbor(TranslateTextRequest v) -> cbor.CborValue:"));
    assert!(src.contains("keys.append(\"Text\")"));
    assert!(src.contains("vals.append(cbor.cbor_text(v.Text))"));
    // Imports: core + endpoints + cbor (the codec), never awsjson/query/restxml.
    assert!(src.contains("import aws_core.cbor"));
    assert!(!src.contains("import aws_core.awsjson"));
    // Error dispatch from the body `__type`.
    assert!(src.contains("def translate_error_from_code(str code) -> TranslateError:"));
}

#[test]
fn cbor_cloudwatch_float_and_timestamp_encoding() {
    // CloudWatch (query->cbor upstream) exercises the fidelity-critical encodings:
    // a `double` member is cbor_double (ai 27), an integer is cbor_int, a
    // timestamp is tag-1 epoch via datetime.to_timestamp, and a list of doubles
    // nests through cbor_list. These drive the byte-diff gate (tests/cbor_byte_diff.rs).
    let (src, cov) = aws_codegen::generate_from_json(&cloudwatch_model()).unwrap();
    assert!(src.contains("def put_metric_data(self, PutMetricDataInput input) -> bytes:"));
    assert!(src.contains("def metric_datum_to_cbor(MetricDatum v) -> cbor.CborValue:"));
    assert!(src.contains("vals.append(cbor.cbor_double(u")); // Value: double shape
    assert!(src.contains("vals.append(cbor.cbor_int(u")); // StorageResolution: integer
    assert!(src.contains("cbor.cbor_timestamp(datetime.to_timestamp(u")); // Timestamp
    assert!(src.contains("import datetime")); // pulled in by the timestamp member
                                              // targetPrefix is the rpc-v2 service shape in the URI (NOT "CloudWatch").
    assert!(src.contains("\"GraniteServiceVersion20100801\""));
    // CloudWatch has no non-text-keyed maps, so every op is covered.
    assert_eq!(
        cov.operations_skipped, 0,
        "no cbor op should be skipped for CloudWatch"
    );
    assert!(cov.operations_methods >= 50);
}

#[test]
fn supported_protocols_accepted_unknown_rejected() {
    // The emitter now spans the awsJson, rest-json, rest-xml, query/ec2 and
    // smithy-rpc-v2-cbor protocols; all are accepted. A protocol it does not emit
    // yet is rejected with a clear message.
    for proto in [
        "json",
        "rest-json",
        "rest-xml",
        "query",
        "ec2",
        "smithy-rpc-v2-cbor",
    ] {
        let m = format!(
            r#"{{"metadata":{{"protocol":"{proto}","apiVersion":"2021-01-01","endpointPrefix":"x"}},"operations":{{}},"shapes":{{}}}}"#
        );
        assert!(
            aws_codegen::generate_from_json(&m).is_ok(),
            "protocol {proto} should be accepted"
        );
    }
    // A made-up / event-stream-only protocol the generator does not emit is
    // rejected with a clear message.
    let m = r#"{"metadata":{"protocol":"smithy-rpc-v2-protobuf","endpointPrefix":"x"},"operations":{},"shapes":{}}"#;
    let err = aws_codegen::generate_from_json(m).unwrap_err();
    assert!(err.contains("smithy-rpc-v2-protobuf"), "{err}");
    assert!(err.contains("unsupported protocol"), "{err}");
}

// --- Lambda (rest-json) ------------------------------------------------------

#[test]
fn checked_in_lambda_output_is_current() {
    let (src, _cov) = generate_lambda();
    let checked = repo_root().join("generated/lambda/src/lambda.zap");
    let on_disk = std::fs::read_to_string(&checked)
        .unwrap_or_else(|e| panic!("reading {}: {e}", checked.display()));
    assert_eq!(
        src, on_disk,
        "generated/lambda/src/lambda.zap is stale — re-run: \
         cargo run -- models/lambda/2015-03-31/service-2.json --package generated/lambda --name lambda"
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
    assert!(src.contains("restjson.rest_json_raw_payload(b, str(input.Payload.unwrap_or(bytes()))"));
    assert!(src.contains("struct PutFunctionConcurrencyDocument:"));
    assert!(src.contains("restjson.rest_json_document(b, doc.to_json())"));

    // A string enum bound to a header/query is carried as its plain wire string.
    assert!(src.contains("# wire string of the InvocationType enum (header binding)"));

    // Error dispatch and a yield-based paginator threading the Marker token.
    assert!(src.contains("enum LambdaError:"));
    assert!(src.contains("def lambda__error_from_code(str code) -> LambdaError:"));
    assert!(src.contains("def paginate_list_functions(self, ListFunctionsRequest input):"));
    assert!(src.contains("auto np = core.next_page_json(page.body, \"NextMarker\")"));
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
        "generated/cloudfront/src/cloudfront.zap",
    );
}

#[test]
fn checked_in_sdb_output_is_current() {
    assert_current("sdb", "2009-04-15", "generated/sdb/src/sdb.zap");
}

#[test]
fn checked_in_ec2_output_is_current() {
    assert_current("ec2", "2016-11-15", "generated/ec2/src/ec2.zap");
}

#[test]
fn checked_in_sns_output_is_current() {
    assert_current("sns", "2010-03-31", "generated/sns/src/sns.zap");
}

#[test]
fn checked_in_iam_output_is_current() {
    assert_current("iam", "2010-05-08", "generated/iam/src/iam.zap");
}

#[test]
fn checked_in_s3_output_is_current() {
    assert_current("s3", "2006-03-01", "generated/s3/src/s3.zap");
}

#[test]
fn s3_restxml_contract_shape() {
    let (src, cov) = generate_with_sidecar("s3", "2006-03-01");
    // The pinned S3 model (botocore 1.43.121): 116 ops. Most generate; the rest
    // are document-skipped for v0 emitter limits that remain after #425 bound the
    // bool/timestamp/list[str] slots (optional httpPayload structs (#427),
    // list[str]/list[enum] headers, non-derivable payloads). Bumping the
    // pin can move these — update this count and keep the floors as the contract.
    assert_eq!(cov.operations_total, 116);
    assert!(
        cov.operations_methods >= 70,
        "methods: {}",
        cov.operations_methods
    );
    assert!(cov.operations_skipped > 0, "complex S3 payloads skip");
    assert!(cov.error_variants >= 15, "errors: {}", cov.error_variants);
    // Protocol seam: a service-name function, SigV4 service "s3", plain structs.
    assert!(src.contains("# Protocol: rest-xml (SigV4 service s3)"));
    assert!(src.contains("def s3_service() -> str:"));
    assert!(src.contains("    return \"s3\""));
    assert!(
        !src.contains("@derive(Json)\nstruct"),
        "rest-xml structs are plain carriers"
    );
    // The four byte-diffed ops (tests/s3_byte_diff.rs) generate: a bucket op, a
    // service listing, an object GET with a greedy {Key+} label, and an object
    // PUT with a raw httpPayload body.
    assert!(src.contains("def head_bucket(self, HeadBucketRequest input) -> str:"));
    assert!(src.contains("def list_buckets(self, ListBucketsRequest input) -> str:"));
    assert!(src.contains("def list_parts(self, ListPartsRequest input) -> str:"));
    assert!(src.contains("def upload_part(self, UploadPartRequest input) -> str:"));
    assert!(src.contains("greedy_labels[\"Key\"] = input.Key"));
    assert!(src.contains(
        "restxml.rest_xml_raw_payload(b, str(input.Body.unwrap_or(bytes())), \"application/octet-stream\")"
    ));
    // zaplang-io/zap#425 bound the bool/timestamp/list[str] URI/query/header
    // types, so ops formerly skipped for a `DateTime` header (GetObject's
    // `IfModifiedSince`) or a bool header (PutObject's `BucketKeyEnabled`) now
    // generate a method.
    assert!(src.contains("def get_object(self, GetObjectRequest input) -> str:"));
    assert!(src.contains("def put_object(self, PutObjectRequest input) -> str:"));
    // GetObject's timestamp headers render with the RFC-822 (HTTP-date) default.
    assert!(src.contains(
        "datetime.strftime(input.IfModifiedSince.unwrap(), \"%a, %d %b %Y %H:%M:%S GMT\")"
    ));
    // Residual #425 skips remain for a list[str] bound to a header
    // (ListObjectsV2's `OptionalObjectAttributes`).
    assert!(src.contains(
        "ListObjectsV2 (httpHeader `OptionalObjectAttributes` has unsupported type list[str])"
    ));
    // zaplang-io/zap#427 closed the optional httpPayload structure gap:
    // CreateBucket (optional `CreateBucketConfiguration`) now generates a method,
    // guarding the body on the member being present and sending none otherwise.
    assert!(src.contains("def create_bucket(self, CreateBucketRequest input) -> str:"));
    assert!(src.contains("if input.CreateBucketConfiguration.is_some():"));
    assert!(!src.contains("CreateBucketConfiguration` is optional"));
}

#[test]
fn s3_generation_is_deterministic() {
    assert_eq!(
        generate_with_sidecar("s3", "2006-03-01").0,
        generate_with_sidecar("s3", "2006-03-01").0
    );
}

#[test]
fn restxml_contract_shape() {
    let (src, cov) = generate_with_sidecar("cloudfront", "2015-09-17");
    assert_eq!(cov.operations_total, 22);
    // #426: every CloudFront op now serializes (bool + nested collection bodies).
    assert_eq!(
        cov.operations_methods, 22,
        "methods: {}",
        cov.operations_methods
    );
    assert_eq!(cov.operations_skipped, 0);
    // Protocol seam: a service-name function, plain structs (no @derive(Json)).
    assert!(src.contains("# Protocol: rest-xml"));
    assert!(src.contains("def cloudfront_service() -> str:"));
    assert!(src.contains("    return \"cloudfront\""));
    assert!(
        !src.contains("@derive(Json)\nstruct"),
        "rest-xml structs are plain carriers"
    );
    // A namespaced XML document body with a nested struct + wrapped list.
    assert!(src.contains("restxml.rest_xml_root_ns(\"InvalidationBatch\","));
    assert!(src.contains("restxml.rest_xml_struct(root, \"Paths\")"));
    assert!(src.contains("restxml.rest_xml_wrapped_list(n0, \"Items\", \"Path\","));
    assert!(src.contains("restxml.rest_xml_document(b, body)"));
    // #426: a boolean body member routes through the per-file _xml_bool helper.
    assert!(src.contains("def cloudfront_xml_bool(bool b) -> str:"));
    assert!(src.contains("cloudfront_xml_bool("));
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
    assert!(src.contains("auto p = query.query_params(\"GetAttributes\", \"2009-04-15\")"));
    assert!(src.contains("query.query_flat_list(p, \"AttributeNames\","));
    assert!(src.contains("query.query_bool(input.ConsistentRead.unwrap())"));
    assert!(src.contains("return query.query_request(self.creds, sdb_service(), self.region, p)"));
}

#[test]
fn ec2_contract_shape() {
    // EC2 is productionized to the full current model (2016-11-15, #357): 811 ops,
    // the "large model" the drift check + generator must handle. Bumping the pin
    // can move the exact total — update it here and keep the floor as the contract.
    let (src, cov) = generate_with_sidecar("ec2", "2016-11-15");
    assert_eq!(cov.operations_total, 811);
    // #426: every ec2 op now serializes (Filters list-of-struct, nested structs).
    assert_eq!(
        cov.operations_methods, 811,
        "methods: {}",
        cov.operations_methods
    );
    assert_eq!(cov.operations_skipped, 0);
    assert!(src.contains("# Protocol: ec2"));
    assert!(src.contains("def ec2_service() -> str:"));
    assert!(src.contains("    return \"ec2\""));
    assert!(src.contains("auto p = query.query_params(\"MonitorInstances\", \"2016-11-15\")"));
    // ec2 capitalizes the key and always flattens the list.
    assert!(src.contains("query.query_flat_list(p, \"InstanceId\", input.InstanceIds)"));
    assert!(src.contains("query.query_scalar(p, \"DryRun\","));
    // #426: the list-of-struct Filters ops (DescribeInstances / DescribeRegions)
    // now generate via a per-shape serializer function.
    assert!(src.contains("def get_console_output(self, GetConsoleOutputRequest input) -> str:"));
    assert!(src.contains("def describe_instances("));
    assert!(src.contains("def describe_regions("));
    assert!(src.contains("_to_query(list[query.QueryPair] p, str prefix,"));
}

#[test]
fn sns_contract_shape() {
    let (src, cov) = generate_with_sidecar("sns", "2010-03-31");
    assert_eq!(cov.operations_total, 42);
    // #426: every SNS op now serializes (map + list-of-struct bodies covered).
    assert_eq!(
        cov.operations_methods, 42,
        "methods: {}",
        cov.operations_methods
    );
    assert_eq!(cov.operations_skipped, 0);
    assert!(cov.error_variants >= 15, "errors: {}", cov.error_variants);
    assert!(src.contains("# Protocol: query"));
    assert!(src.contains("def sns_service() -> str:"));
    assert!(src.contains("    return \"sns\""));
    assert!(src.contains("auto p = query.query_params(\"GetTopicAttributes\", \"2010-03-31\")"));
    assert!(src.contains("p = query.query_scalar(p, \"TopicArn\", input.TopicArn)"));
    assert!(src.contains("def set_topic_attributes(self, SetTopicAttributesInput input) -> str:"));
    // #426: Publish (map body) and CreateTopic (list-of-struct) now generate; the
    // map goes through the codec's query_map helper.
    assert!(src.contains("def publish("));
    assert!(src.contains("def create_topic("));
    assert!(src.contains("p = query.query_map(p, \"Attributes\", \"key\", \"value\","));
    assert!(src.contains("enum SNSError:") || src.contains("enum SnsError:"));
}

#[test]
fn iam_contract_shape() {
    let (src, cov) = generate_with_sidecar("iam", "2010-05-08");
    assert_eq!(cov.operations_total, 180);
    // #426: every IAM op now serializes (list-of-struct Tags, nested structs).
    assert_eq!(
        cov.operations_methods, 180,
        "methods: {}",
        cov.operations_methods
    );
    assert_eq!(cov.operations_skipped, 0);
    assert!(cov.error_variants >= 15, "errors: {}", cov.error_variants);
    assert!(src.contains("# Protocol: query"));
    assert!(src.contains("def iam_service() -> str:"));
    assert!(src.contains("    return \"iam\""));
    // The ticket's named ops GetUser / ListUsers generate and are byte-diffed.
    assert!(src.contains("def get_user(self, GetUserRequest input) -> str:"));
    assert!(src.contains("def list_users(self, ListUsersRequest input) -> str:"));
    assert!(src.contains("auto p = query.query_params(\"ListUsers\", \"2010-05-08\")"));
    assert!(src.contains("p = query.query_scalar(p, \"MaxItems\", str(input.MaxItems.unwrap()))"));
    // #426: CreateUser (Tags list-of-struct) now generates.
    assert!(src.contains("def create_user("));
}

#[test]
fn xml_family_generation_is_deterministic() {
    assert_eq!(
        generate_with_sidecar("cloudfront", "2015-09-17").0,
        generate_with_sidecar("cloudfront", "2015-09-17").0
    );
    assert_eq!(
        generate_with_sidecar("ec2", "2016-11-15").0,
        generate_with_sidecar("ec2", "2016-11-15").0
    );
    assert_eq!(
        generate_with_sidecar("sns", "2010-03-31").0,
        generate_with_sidecar("sns", "2010-03-31").0
    );
    assert_eq!(
        generate_with_sidecar("iam", "2010-05-08").0,
        generate_with_sidecar("iam", "2010-05-08").0
    );
}

// --- #364 broad rollout: every manifested package regenerates byte-identically -

/// The whole generated SDK is manifest-driven (#364): `models/manifest.json` is
/// the single source of truth, and every service listed there must have a
/// checked-in `generated/<pkg>/` package that regenerates byte-for-byte from its
/// pinned model (+ paginators sidecar when present). `<pkg>` is the service name
/// with `-` mapped to `_` (a valid Zap identifier), matching
/// `tools/manifest_services.py` and the CI determinism step. This is the
/// toolchain-free determinism gate for the broad rollout: it covers all services
/// at once (the hand-written per-service `checked_in_*_output_is_current` tests
/// above remain as focused, coverage-asserting spot checks).
#[test]
fn all_checked_in_packages_are_current() {
    let manifest_path = repo_root().join("models/manifest.json");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", manifest_path.display())),
    )
    .expect("models/manifest.json is valid JSON");
    let services = manifest["services"]
        .as_array()
        .expect("manifest.services is an array");
    assert!(
        services.len() >= 400,
        "expected the broad-rollout manifest (>=400 services), found {}",
        services.len()
    );

    let mut stale = Vec::new();
    for entry in services {
        let svc = entry["service"].as_str().expect("service is a string");
        let ver = entry["api_version"]
            .as_str()
            .expect("api_version is a string");
        let pkg = svc.replace('-', "_");

        let model = read_model(&format!("models/{svc}/{ver}/service-2.json"));
        // Paginators are an optional sidecar; the CLI picks it up when present.
        let pag_path = repo_root().join(format!("models/{svc}/{ver}/paginators-1.json"));
        let pag = std::fs::read_to_string(&pag_path).ok();
        let (src, _cov) = aws_codegen::generate_from_json_with_paginators(&model, pag.as_deref())
            .unwrap_or_else(|e| panic!("generating {svc}: {e}"));

        let client_rel = format!("generated/{pkg}/src/{pkg}.zap");
        let on_disk = std::fs::read_to_string(repo_root().join(&client_rel))
            .unwrap_or_else(|e| panic!("reading {client_rel}: {e}"));
        if src != on_disk {
            stale.push(client_rel);
        }

        let toml_rel = format!("generated/{pkg}/zap.toml");
        let toml_on_disk = std::fs::read_to_string(repo_root().join(&toml_rel))
            .unwrap_or_else(|e| panic!("reading {toml_rel}: {e}"));
        if aws_codegen::package_manifest(&pkg) != toml_on_disk {
            stale.push(toml_rel);
        }
    }
    assert!(
        stale.is_empty(),
        "{} generated file(s) are stale — run `make generate`: {:?}",
        stale.len(),
        stale
    );
}

// zaplang-io/zap#427: a structured httpPayload body on rest-json. A payload that
// is serializable-but-not-derivable (nested collection members) is serialized by
// the explicit #424 serializer and carried as the raw application/json body; an
// optional one guards the whole body on `is_some()` and sends none when absent.
const REST_PAYLOAD: &str = r#"{
  "metadata":{"protocol":"rest-json","endpointPrefix":"svc","serviceId":"Svc","jsonVersion":"1.1"},
  "operations":{
    "PutReq":{"name":"PutReq","http":{"method":"POST","requestUri":"/r/{Id}"},
      "input":{"shape":"PutReqRequest"}},
    "PutOpt":{"name":"PutOpt","http":{"method":"POST","requestUri":"/o/{Id}"},
      "input":{"shape":"PutOptRequest"}}},
  "shapes":{
    "S":{"type":"string"},
    "StrList":{"type":"list","member":{"shape":"S"}},
    "Doc":{"type":"structure","members":{"Name":{"shape":"S"},"Items":{"shape":"StrList"}}},
    "PutReqRequest":{"type":"structure","required":["Id","Body"],
      "members":{"Id":{"shape":"S","location":"uri","locationName":"Id"},
        "Body":{"shape":"Doc"}},"payload":"Body"},
    "PutOptRequest":{"type":"structure","required":["Id"],
      "members":{"Id":{"shape":"S","location":"uri","locationName":"Id"},
        "Body":{"shape":"Doc"}},"payload":"Body"}}}"#;

#[test]
fn rest_json_structured_payload_required_and_optional() {
    let (src, cov) = aws_codegen::generate_from_json(REST_PAYLOAD).unwrap();
    // Both ops now generate — the structured payload is no longer skipped.
    assert_eq!(cov.operations_skipped, 0, "{src}");

    // `Doc` holds a list -> serializable but not derivable -> explicit serializer.
    assert!(src.contains("def doc_to_json(Doc v) -> str:"), "{src}");

    // Required payload: serialize straight off `input.Body` into the raw body.
    assert!(
        src.contains(
            "restjson.rest_json_raw_payload(b, doc_to_json(input.Body), \"application/json\")"
        ),
        "{src}"
    );

    // Optional payload: guarded; present -> body off the unwrapped `pv`, absent
    // -> the bare binding (no body).
    assert!(src.contains("if input.Body.is_some():"), "{src}");
    assert!(src.contains("auto pv = input.Body.unwrap()"), "{src}");
    assert!(
        src.contains("restjson.rest_json_raw_payload(b, doc_to_json(pv), \"application/json\")"),
        "{src}"
    );
    assert!(
        src.contains(
            "return restjson.rest_json_request(self.creds, bp, svc_service(), self.region, host)"
        ),
        "{src}"
    );
    assert!(
        src.contains(
            "return restjson.rest_json_request(self.creds, b, svc_service(), self.region, host)"
        ),
        "{src}"
    );
}
