# Smoke-test entry point for the generated SQS client (bundled after the
# generated file; see scripts/compile_check.sh). Like vendor/smoke_main.zap but
# for SQS: exercises only the derive-path (flat, derivable) surface so it stands
# alone without the collection serialization that is still a derive follow-up
# (zaplang-io/zap#346): a GetQueueUrl request through the awsJson codec, plus
# error-code dispatch. Fixed credentials; no network. A compile/run gate, not a
# byte-vector test (that is tests/sqs.rs + tools/verify_goldens.py).

def main():
    auto client = sqs_client(credentials("AKIDEXAMPLE", "SECRET"), "us-east-1")
    auto req = client.get_queue_url(GetQueueUrlRequest(QueueName="MyQueue"))
    if len(req) > 0:
        print("get_queue_url: signed request produced")
    match sqs_error_from_code("QueueDoesNotExist"):
        case SQSError.QueueDoesNotExist:
            print("error dispatch: QueueDoesNotExist")
        case _:
            print("error dispatch: unexpected")
    match sqs_error_from_code("SomethingNew"):
        case SQSError.Unknown(code):
            print("error dispatch: unknown -> " + code)
        case _:
            print("error dispatch: unexpected")
