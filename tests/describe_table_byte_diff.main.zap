# End-to-end byte-diff gate for the generated DynamoDB client (#348).
#
# Run as the entry of a consumer zenv project that depends on the generated
# `dynamodb` package + the pinned aws_core package (see scripts/byte_diff_check.sh;
# #339 step 2 retired the vendor/*.zap concatenation). It proves the generator is
# faithful on the wire: it serializes a DynamoDB `DescribeTable` request two ways —
#
#   * GENERATED: the generated `DescribeTableInput` shape's derive(Json)
#     `to_json()` + the generated `dynamodb_protocol()`, signed through the
#     shared awsJson codec; and
#   * HAND-WRITTEN: the reference awsJson 1.0 config built by hand with the
#     known-correct literal body `{"TableName":"Users"}`
#
# — at AWS's published SigV4 example credentials + timestamp, and asserts the two
# are byte-identical. On a match it prints the request verbatim; CI diffs that
# against the golden tests/expected/dynamodb_describe_table.http (the same bytes
# tools/verify_describe_table.py reproduces from scratch). On a mismatch it
# prints both requests, which breaks the golden diff loudly.
#
# The generated client's live method uses awsjson.awsjson_request_now()
# (datetime.now() + endpoint resolution); here we drive the SAME serialization
# through the deterministic awsjson.awsjson_request() so the signature is
# reproducible. The only difference from the live path is the fixed
# timestamp/host — runtime inputs, not anything the generator decides.
import aws_core.core
import aws_core.endpoints
import aws_core.awsjson
import dynamodb

def main():
    auto creds = core.credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
    auto region = "us-east-1"
    auto amz_date = "20150830T123600Z"
    auto date_stamp = "20150830"
    auto host = endpoints.regional_host("dynamodb", region)

    # GENERATED path: the generated input shape + protocol config.
    auto gen_body = dynamodb.DescribeTableInput(TableName="Users").to_json()
    auto generated = awsjson.awsjson_request(
        dynamodb.dynamodb_protocol(),
        creds,
        region,
        host,
        "DescribeTable",
        gen_body,
        amz_date,
        date_stamp,
    )

    # HAND-WRITTEN reference path: config built by hand, known-correct body.
    auto ref_proto = awsjson.awsjson_1_0("DynamoDB_20120810", "dynamodb")
    auto ref_body = "{\"TableName\":\"Users\"}"
    auto handwritten = awsjson.awsjson_request(
        ref_proto,
        creds,
        region,
        host,
        "DescribeTable",
        ref_body,
        amz_date,
        date_stamp,
    )

    if generated == handwritten:
        print(generated)
    else:
        print("GENERATED/HANDWRITTEN BYTE-DIFF MISMATCH")
        print("--- generated ---")
        print(generated)
        print("--- handwritten ---")
        print(handwritten)
