//! Integration tests: the generator is deterministic, the checked-in DynamoDB
//! output is up to date, and the awsJson-only contract + escaping hold.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn dynamodb_model() -> String {
    let p = repo_root().join("models/dynamodb/2012-08-10/service-2.json");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
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
    // The real model: 53 ops, 234 structures, enums + the error set.
    assert_eq!(cov.operations_total, 53);
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
fn non_json_protocol_is_rejected() {
    let m =
        r#"{"metadata":{"protocol":"rest-json","endpointPrefix":"x"},"operations":{},"shapes":{}}"#;
    let err = aws_codegen::generate_from_json(m).unwrap_err();
    assert!(err.contains("awsJson"), "{err}");
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
