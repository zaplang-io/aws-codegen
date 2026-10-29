# Smoke-test entry point for the generated Kinesis client (bundled after the
# generated file; see scripts/compile_check.sh). Like vendor/smoke_main.zap but
# for Kinesis (awsJson 1.1): exercises only the derive-path (flat, derivable)
# surface — a DescribeStreamSummary request through the awsJson codec, plus
# error-code dispatch. Fixed credentials; no network. A compile/run gate, not a
# byte-vector test (that is tests/kinesis.rs + tools/verify_goldens.py).

def main():
    auto client = kinesis_client(credentials("AKIDEXAMPLE", "SECRET"), "us-east-1")
    auto req = client.describe_stream_summary(DescribeStreamSummaryInput(StreamName="exampleStreamName"))
    if len(req) > 0:
        print("describe_stream_summary: signed request produced")
    match kinesis_error_from_code("ResourceNotFoundException"):
        case KinesisError.ResourceNotFoundException:
            print("error dispatch: ResourceNotFoundException")
        case _:
            print("error dispatch: unexpected")
    match kinesis_error_from_code("SomethingNew"):
        case KinesisError.Unknown(code):
            print("error dispatch: unknown -> " + code)
        case _:
            print("error dispatch: unexpected")
