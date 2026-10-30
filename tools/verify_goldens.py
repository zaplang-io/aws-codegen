#!/usr/bin/env python3
"""Independent oracle for the per-service awsJson byte-diff fixtures (#350).

The toolchain-free half of the byte-diff gate for the services added in #350
(SQS, and any later JSON-protocol service). Same role and method as
`tools/verify_describe_table.py` does for DynamoDB (#348), but table-driven so a
new service is one `Vector` entry: it recomputes — from scratch, with only the
Python standard library — the exact on-the-wire awsJson HTTP request bytes for a
chosen operation and diffs them against the checked-in golden under
`tests/expected/`.

Each vector is "the request the generated client must produce": the generated
`<svc>` client serializes the operation input with derive(Json) and dispatches it
through `aws.awsjson` as a POST "/" with the `X-Amz-Target: <prefix>.<Op>`
selector, the `application/x-amz-json-1.<v>` content type, and a real SigV4
signature. The Rust side (`tests/sqs.rs` et al.) reconstructs the same bytes from
the *generated source* + an independent signer and checks the same golden, so the
two implementations must agree. This script is the second, independent SigV4
implementation, so a regression in a fixture — or drift in the signing contract
shared with zaplang-io/aws — is caught even on a runner with no Zap toolchain.

The signer mirrors aws.core's generic canonicalization (lowercase / trim / sort a
header dict) and uses AWS's published SigV4 example credentials + timestamp, the
same fixed inputs as zaplang-io/aws, so these vectors line up byte-for-byte with
the hand-written SDK's own pinned requests.

Usage:
  tools/verify_goldens.py            # check every checked-in golden (CI gate)
  tools/verify_goldens.py --emit      # (re)write every golden from the oracle
"""
import hashlib
import hmac
import os
import sys
from urllib.parse import quote

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED = os.path.join(ROOT, "tests", "expected")

# AWS's published SigV4 example credentials + timestamp (same fixed inputs as
# zaplang-io/aws tests/service_signing.main.zap), so every signature is
# deterministic and independently reproducible with botocore / any SigV4 oracle.
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
ACCESS = "AKIDEXAMPLE"
REGION = "us-east-1"
AMZ = "20150830T123600Z"
DS = "20150830"


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def signing_key(secret, ds, region, svc):
    k = hmac.new(("AWS4" + secret).encode(), ds.encode(), hashlib.sha256).digest()
    k = hmac.new(k, region.encode(), hashlib.sha256).digest()
    k = hmac.new(k, svc.encode(), hashlib.sha256).digest()
    return hmac.new(k, b"aws4_request", hashlib.sha256).digest()


def canonical_headers(headers):
    return "".join(n.lower() + ":" + headers[n].strip() + "\n" for n in sorted(headers))


def signed_headers(headers):
    return ";".join(sorted(n.lower() for n in headers))


def uri_encode(s, slash_safe):
    return quote(s, safe="/-_.~" if slash_safe else "-_.~")


def canonical_uri(path, service):
    enc = uri_encode(path, True)
    if service != "s3":
        enc = uri_encode(enc, True)  # non-S3 double-encodes the path
    return enc


def sign_request(service, method, host, path, body, headers):
    """Build the full HTTP/1.1 request text exactly as aws.core.sign_request."""
    payload_sha = sha(body)
    ch = canonical_headers(headers)
    sh = signed_headers(headers)
    cu = canonical_uri(path, service)
    creq = f"{method}\n{cu}\n\n{ch}\n{sh}\n{payload_sha}"
    scope = f"{DS}/{REGION}/{service}/aws4_request"
    sts = f"AWS4-HMAC-SHA256\n{AMZ}\n{scope}\n{sha(creq)}"
    sig = hmac.new(signing_key(SECRET, DS, REGION, service),
                   sts.encode(), hashlib.sha256).hexdigest()
    auth = (f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, "
            f"SignedHeaders={sh}, Signature={sig}")
    wire = "".join(f"{n.lower()}: {headers[n]}\r\n" for n in sorted(headers))
    wire += f"content-length: {len(body)}\r\n"
    wire += f"authorization: {auth}\r\n"
    target = uri_encode(path, True)
    return (f"{method} {target} HTTP/1.1\r\n{wire}"
            f"Connection: close\r\n\r\n{body}")


class Vector:
    """One operation's awsJson byte-diff fixture."""

    def __init__(self, name, service, prefix, op, json_version, host, body):
        self.name = name
        self.service = service
        self.prefix = prefix
        self.op = op
        self.content_type = f"application/x-amz-json-{json_version}"
        self.host = host
        self.body = body

    @property
    def golden(self):
        return os.path.join(EXPECTED, f"{self.name}.http")

    def request(self):
        headers = {
            "content-type": self.content_type,
            "host": self.host,
            "x-amz-content-sha256": sha(self.body),
            "x-amz-date": AMZ,
            "x-amz-target": f"{self.prefix}.{self.op}",
        }
        return sign_request(self.service, "POST", self.host, "/", self.body, headers)


# The vectors under test. One entry per generated JSON-protocol service.
VECTORS = [
    # SQS GetQueueUrl: a single required `str QueueName`, so derive(Json) encodes
    # it as compact, declaration-order JSON {"QueueName":"MyQueue"} (optional
    # QueueOwnerAWSAccountId omitted while None). awsJson 1.0, target AmazonSQS.
    Vector(
        name="sqs_get_queue_url",
        service="sqs",
        prefix="AmazonSQS",
        op="GetQueueUrl",
        json_version="1.0",
        host="sqs.us-east-1.amazonaws.com",
        body='{"QueueName":"MyQueue"}',
    ),
    # Kinesis DescribeStreamSummary: exercises the awsJson **1.1** path (content
    # type application/x-amz-json-1.1, awsjson_1_1 constructor) that neither
    # DynamoDB nor SQS (both 1.0) covers. StreamName is the first member; derive
    # encodes the one set field as {"StreamName":"exampleStreamName"}.
    Vector(
        name="kinesis_describe_stream_summary",
        service="kinesis",
        prefix="Kinesis_20131202",
        op="DescribeStreamSummary",
        json_version="1.1",
        host="kinesis.us-east-1.amazonaws.com",
        body='{"StreamName":"exampleStreamName"}',
    ),
    # Kinesis PutRecords: a **list-of-structures** document body (zaplang-io/
    # zap#424). `Records` is a required list of PutRecordsRequestEntry, each a
    # derivable struct serialized via its `.to_json()` (declaration order: Data
    # as a base64 blob, then PartitionKey); the list wraps them in a JSON array,
    # then StreamName follows in model order. The explicit `<shape>_to_json`
    # serializer produces exactly this (blob -> base64 "aGVsbG8=" for b"hello").
    Vector(
        name="kinesis_put_records",
        service="kinesis",
        prefix="Kinesis_20131202",
        op="PutRecords",
        json_version="1.1",
        host="kinesis.us-east-1.amazonaws.com",
        body='{"Records":[{"Data":"aGVsbG8=","PartitionKey":"pk1"}],'
        '"StreamName":"my-stream"}',
    ),
]


def main(argv):
    emit = "--emit" in argv[1:]
    failures = 0
    for v in VECTORS:
        computed = v.request()
        if emit:
            with open(v.golden, "w", newline="") as fh:
                fh.write(computed)
            print(f"wrote {os.path.relpath(v.golden, ROOT)} ({len(computed)} bytes)")
            continue
        try:
            with open(v.golden, "r", newline="") as fh:
                expected = fh.read()
        except FileNotFoundError:
            sys.stderr.write(f"missing golden {v.golden}; run with --emit\n")
            failures += 1
            continue
        if computed != expected:
            sys.stderr.write(
                f"MISMATCH {v.name}\n"
                f"--- computed ---\n{computed!r}\n"
                f"--- expected ---\n{expected!r}\n"
            )
            failures += 1
        else:
            print(f"ok {v.name} — generated byte-diff vector verified")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
