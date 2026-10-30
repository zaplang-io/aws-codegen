# Smoke-test entry for the generated DynamoDB client, as a real consumer of the
# per-service zenv package (scripts/compile_check.sh materializes a zenv and runs
# this as src/main.zap). Imports the service package `dynamodb` and the aws_core
# runtime via #283 module imports — the bundling/concatenation crutch is retired.
# Exercises only the derive-path (flat, derivable) surface so it stands alone
# without the collection serialization that is still a derive follow-up
# (zaplang-io/zap#346): a DescribeTable request through the awsJson codec, plus
# error-code dispatch. Fixed credentials; no network. A compile/run gate, not a
# byte-vector test (that is #348).
import aws_core.core
import dynamodb

def main():
    auto client = dynamodb.dynamodb_client(core.credentials("AKIDEXAMPLE", "SECRET"), "us-east-1")
    auto req = client.describe_table(dynamodb.DescribeTableInput(TableName="Users"))
    if len(req) > 0:
        print("describe_table: signed request produced")
    match dynamodb.dynamodb_error_from_code("ResourceNotFoundException"):
        case dynamodb.DynamoDBError.ResourceNotFoundException:
            print("error dispatch: ResourceNotFoundException")
        case _:
            print("error dispatch: unexpected")
    match dynamodb.dynamodb_error_from_code("SomethingNew"):
        case dynamodb.DynamoDBError.Unknown(code):
            print("error dispatch: unknown -> " + code)
        case _:
            print("error dispatch: unexpected")
