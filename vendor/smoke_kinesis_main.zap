# Smoke-test entry for the generated Kinesis client, as a real consumer of the
# per-service zenv package (scripts/compile_check.sh materializes a zenv and runs
# this as src/main.zap). Like vendor/smoke_main.zap but for Kinesis (awsJson
# 1.1): imports the service package `kinesis` and the aws_core runtime via #283
# module imports. Exercises only the derive-path (flat, derivable) surface — a
# DescribeStreamSummary request through the awsJson codec, plus error-code
# dispatch. Fixed credentials; no network. A compile/run gate, not a byte-vector
# test (that is tests/kinesis.rs + tools/verify_goldens.py).
import aws_core.core
import kinesis

def main():
    auto client = kinesis.kinesis_client(core.credentials("AKIDEXAMPLE", "SECRET"), "us-east-1")
    auto req = client.describe_stream_summary(kinesis.DescribeStreamSummaryInput(StreamName="exampleStreamName"))
    if len(req) > 0:
        print("describe_stream_summary: signed request produced")
    match kinesis.kinesis_error_from_code("ResourceNotFoundException"):
        case kinesis.KinesisError.ResourceNotFoundException:
            print("error dispatch: ResourceNotFoundException")
        case _:
            print("error dispatch: unexpected")
    match kinesis.kinesis_error_from_code("SomethingNew"):
        case kinesis.KinesisError.Unknown(code):
            print("error dispatch: unknown -> " + code)
        case _:
            print("error dispatch: unexpected")
