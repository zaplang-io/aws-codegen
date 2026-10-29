#!/usr/bin/env python3
"""Independent oracle for the DynamoDB DescribeTable byte-diff fixture (#348).

This is the toolchain-free half of the byte-diff gate. It recomputes — from
scratch, with only the Python standard library — the exact on-the-wire awsJson
1.0 HTTP request bytes for a DynamoDB `DescribeTable` call, and diffs them against
the checked-in golden `tests/expected/dynamodb_describe_table.http`.

The golden is "the request the HAND-WRITTEN reference produces": DescribeTable
rides the derive path end to end, so the hand-written `aws.dynamodb` /
`aws.awsjson` codec serializes it as a POST "/" with body `{"TableName":"Users"}`,
the `X-Amz-Target: DynamoDB_20120810.DescribeTable` selector, the
`application/x-amz-json-1.0` content type, and a real SigV4 signature. The Zap
side (that the GENERATED client actually PRODUCES these bytes) is proven under the
real toolchain by `tests/describe_table_byte_diff.main.zap`; the generator side
(that the generated source yields exactly this body/target/content-type/path) is
proven host-only by `tests/byte_diff.rs`. This script is a third, independent
implementation of the SigV4 algorithm, so a regression in the fixture — or drift
in the signing contract shared with zaplang-io/aws — is caught even on a runner
with no Zap toolchain.

The signer mirrors aws.core's generic canonicalization (lowercase / trim / sort a
header dict) and the published AWS SigV4 example credentials + timestamp used by
zaplang-io/aws tests/expected/service_signing.expected, so the DynamoDB vectors
here line up byte-for-byte with the hand-written SDK's own pinned requests.

Usage:
  tools/verify_describe_table.py            # check the checked-in golden (CI gate)
  tools/verify_describe_table.py --emit      # (re)write the golden from the oracle
"""
import hashlib
import hmac
import os
import sys
from urllib.parse import quote

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "tests", "expected", "dynamodb_describe_table.http")

# AWS's published SigV4 example credentials + timestamp (same fixed inputs as
# zaplang-io/aws tests/service_signing.main.zap), so the signature is
# deterministic and independently reproducible with botocore / any SigV4 oracle.
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
ACCESS = "AKIDEXAMPLE"
REGION = "us-east-1"
AMZ = "20150830T123600Z"
DS = "20150830"

# The one DescribeTable call under test. Table "Users" matches the smoke harness.
SERVICE = "dynamodb"
TARGET_PREFIX = "DynamoDB_20120810"
OPERATION = "DescribeTable"
CONTENT_TYPE = "application/x-amz-json-1.0"
HOST = "dynamodb.us-east-1.amazonaws.com"
# derive(Json) on `struct DescribeTableInput: str TableName` encodes a single
# required string field as compact, declaration-order JSON (zaplang-io/zap#346).
BODY = '{"TableName":"Users"}'


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def signing_key(secret, ds, region, svc):
    k = hmac.new(("AWS4" + secret).encode(), ds.encode(), hashlib.sha256).digest()
    k = hmac.new(k, region.encode(), hashlib.sha256).digest()
    k = hmac.new(k, svc.encode(), hashlib.sha256).digest()
    return hmac.new(k, b"aws4_request", hashlib.sha256).digest()


def canonical_headers(headers):
    out = ""
    for name in sorted(headers):
        out += name.lower() + ":" + headers[name].strip() + "\n"
    return out


def signed_headers(headers):
    return ";".join(sorted(n.lower() for n in headers))


def uri_encode(s, slash_safe):
    return quote(s, safe="/-_.~" if slash_safe else "-_.~")


def canonical_uri(path, service):
    enc = uri_encode(path, True)
    if service != "s3":
        enc = uri_encode(enc, True)
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


def describe_table_request():
    headers = {
        "content-type": CONTENT_TYPE,
        "host": HOST,
        "x-amz-content-sha256": sha(BODY),
        "x-amz-date": AMZ,
        "x-amz-target": f"{TARGET_PREFIX}.{OPERATION}",
    }
    return sign_request(SERVICE, "POST", HOST, "/", BODY, headers)


def main(argv):
    computed = describe_table_request()
    if "--emit" in argv[1:]:
        with open(GOLDEN, "w", newline="") as fh:
            fh.write(computed)
        print(f"wrote {os.path.relpath(GOLDEN, ROOT)} ({len(computed)} bytes)")
        return 0
    try:
        with open(GOLDEN, "r", newline="") as fh:
            expected = fh.read()
    except FileNotFoundError:
        sys.stderr.write(f"missing golden {GOLDEN}; run with --emit\n")
        return 1
    if computed != expected:
        sys.stderr.write(
            "MISMATCH dynamodb_describe_table\n"
            f"--- computed ---\n{computed!r}\n"
            f"--- expected ---\n{expected!r}\n"
        )
        return 1
    print("ok dynamodb_describe_table — generated byte-diff vector verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
