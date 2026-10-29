# Smoke-test entry point for the generated client (bundled after the generated
# file; see scripts/compile_check.sh). Exercises only the derive-path (flat,
# derivable) surface so it stands alone without the collection serialization
# that is still a derive follow-up (zaplang-io/zap#346): a DescribeTable request
# through the awsJson codec, plus error-code dispatch. Fixed credentials; no
# network. This is a compile/run gate, not a byte-vector test (that is #348).

def main():
    auto client = dynamodb_client(credentials("AKIDEXAMPLE", "SECRET"), "us-east-1")
    auto req = client.describe_table(DescribeTableInput(TableName="Users"))
    if len(req) > 0:
        print("describe_table: signed request produced")
    match dynamodb_error_from_code("ResourceNotFoundException"):
        case DynamoDBError.ResourceNotFoundException:
            print("error dispatch: ResourceNotFoundException")
        case _:
            print("error dispatch: unexpected")
    match dynamodb_error_from_code("SomethingNew"):
        case DynamoDBError.Unknown(code):
            print("error dispatch: unknown -> " + code)
        case _:
            print("error dispatch: unexpected")
