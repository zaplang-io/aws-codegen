# Smoke-test entry for the generated SQS client, as a real consumer of the
# per-service zenv package (scripts/compile_check.sh materializes a zenv and runs
# this as src/main.zap). Like vendor/smoke_main.zap but for SQS: imports the
# service package `sqs` and the aws_core runtime via #283 module imports.
# Exercises only the derive-path (flat, derivable) surface so it stands alone
# without the collection serialization that is still a derive follow-up
# (zaplang-io/zap#346): a GetQueueUrl request through the awsJson codec, plus
# error-code dispatch. Fixed credentials; no network. A compile/run gate, not a
# byte-vector test (that is tests/sqs.rs + tools/verify_goldens.py).
import aws_core.core
import sqs

def main():
    auto client = sqs.sqs_client(core.credentials("AKIDEXAMPLE", "SECRET"), "us-east-1")
    auto req = client.get_queue_url(sqs.GetQueueUrlRequest(QueueName="MyQueue"))
    if len(req) > 0:
        print("get_queue_url: signed request produced")
    match sqs.sqs_error_from_code("QueueDoesNotExist"):
        case sqs.SQSError.QueueDoesNotExist:
            print("error dispatch: QueueDoesNotExist")
        case _:
            print("error dispatch: unexpected")
    match sqs.sqs_error_from_code("SomethingNew"):
        case sqs.SQSError.Unknown(code):
            print("error dispatch: unknown -> " + code)
        case _:
            print("error dispatch: unexpected")
