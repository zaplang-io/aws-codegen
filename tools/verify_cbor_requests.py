#!/usr/bin/env python3
"""Independent oracle for the generated smithy-rpc-v2-cbor clients (zaplang-io/
zap#428 part 2).

A second, toolchain-free implementation of the on-the-wire request bytes a
generated cbor client produces, so the byte-diff golden is provably genuine even
on a runner with no Zap toolchain and no botocore. It:

  * canonically CBOR-encodes two representative operation bodies — CloudWatch
    ``PutMetricData`` and Translate ``TranslateText`` — with a pure-stdlib
    encoder, and asserts the bytes equal the values botocore's
    ``RpcV2CBORSerializer`` produces (pinned in zaplang-io/aws
    ``tests/expected/cbor_codec.expected`` and reproduced by that repo's
    ``tools/verify_vectors.py`` against botocore); and
  * SigV4-signs the CloudWatch ``PutMetricData`` request over the CBOR body with
    AWS's published example credentials/timestamp and emits the full HTTP/1.1
    request bytes.

Default run verifies the checked-in golden matches this re-derivation; ``--emit``
re-pins it.

  tools/verify_cbor_requests.py          # verify the golden (CI; blocking)
  tools/verify_cbor_requests.py --emit   # re-pin the golden after an intended change
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GOLDEN = REPO_ROOT / "tests" / "expected" / "cbor_cloudwatch_put_metric_data.http"

# AWS's published SigV4 example credentials + timestamp (the same fixed inputs
# the hand-written SDK and the other aws-codegen oracles pin), so the signed
# output is deterministic and reproducible.
ACCESS = "AKIDEXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
REGION = "us-east-1"
AMZ_DATE = "20150830T123600Z"
DATE_STAMP = "20150830"

# The botocore-verified CBOR bodies for the two pinned operations (hex). These
# are copied from zaplang-io/aws tests/expected/cbor_codec.expected, where they
# were driven through botocore's own RpcV2CBORSerializer (aws #428 part 1). The
# generated client, driven with the same inputs, must reproduce these bytes.
CLOUDWATCH_PUT_METRIC_DATA_BODY_HEX = "a2694e616d6573706163656a4d794170702f50726f646a4d65747269634461746182a46a4d65747269634e616d65674c6174656e63796556616c7565fb405900000000000064556e69746c4d696c6c697365636f6e64737153746f726167655265736f6c7574696f6e01a36a4d65747269634e616d65664572726f72736556616c7565fb3fe000000000000064556e697465436f756e74"
TRANSLATE_TRANSLATE_TEXT_BODY_HEX = "a364546578746c48656c6c6f2c20776f726c6472536f757263654c616e6775616765436f646562656e725461726765744c616e6775616765436f6465626573"


# --- a pure-stdlib canonical CBOR encoder (mirrors aws_core.cbor / botocore) ---


class Tagged:
    """A CBOR tag-1 unix-timestamp wrapper (integer epoch seconds)."""

    def __init__(self, epoch: int) -> None:
        self.epoch = epoch


class F32:
    """A 32-bit single-precision float (the AWS ``float`` shape, ai 26)."""

    def __init__(self, value: float) -> None:
        self.value = value


def _head(major: int, n: int) -> bytes:
    base = major << 5
    if n < 24:
        return bytes([base + n])
    if n < 256:
        return bytes([base + 24, n])
    if n < 65536:
        return bytes([base + 25]) + n.to_bytes(2, "big")
    if n < 4294967296:
        return bytes([base + 26]) + n.to_bytes(4, "big")
    return bytes([base + 27]) + n.to_bytes(8, "big")


def cbor_encode(value) -> bytes:
    if isinstance(value, bool):
        return bytes([(7 << 5) + (21 if value else 20)])
    if value is None:
        return bytes([(7 << 5) + 22])
    if isinstance(value, Tagged):
        return bytes([(6 << 5) + 1]) + _head(0, value.epoch)
    if isinstance(value, int):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)
    if isinstance(value, F32):
        return bytes([(7 << 5) + 26]) + struct.pack(">f", value.value)
    if isinstance(value, float):
        return bytes([(7 << 5) + 27]) + struct.pack(">d", value)
    if isinstance(value, str):
        enc = value.encode("utf-8")
        return _head(3, len(enc)) + enc
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, list):
        out = _head(4, len(value))
        for item in value:
            out += cbor_encode(item)
        return out
    if isinstance(value, dict):
        # A structure / map: text keys in insertion order (botocore does NOT sort
        # struct keys), absent members already omitted by the caller.
        out = _head(5, len(value))
        for k, v in value.items():
            out += cbor_encode(str(k))
            out += cbor_encode(v)
        return out
    raise TypeError(f"unencodable CBOR value: {value!r}")


# --- independent SigV4 (mirrors aws_core.core.sign_request over a bytes body) --


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def _quote_path(path: str) -> str:
    out = []
    for b in path.encode("utf-8"):
        c = chr(b)
        if c.isalnum() or c in "-_.~/":
            out.append(c)
        else:
            out.append(f"%{b:02X}")
    return "".join(out)


def _canonical_uri(path: str, service: str) -> str:
    once = _quote_path(path)
    return once if service == "s3" else _quote_path(once)


def sign_request(service: str, host: str, path: str, body: bytes) -> bytes:
    """Build the full HTTP/1.1 request bytes exactly as aws_core.cbor.cbor_sign:
    the rpc-v2 header set + SigV4 over the CBOR body + the binary body."""
    body_sha = hashlib.sha256(body).hexdigest()
    headers = {
        "accept": "application/cbor",
        "host": host,
        "smithy-protocol": "rpc-v2-cbor",
        "x-amz-content-sha256": body_sha,
        "x-amz-date": AMZ_DATE,
    }
    if body:
        headers["content-type"] = "application/cbor"

    ordered = sorted((n.lower(), v) for n, v in headers.items())
    canon_headers = "".join(f"{n}:{v.strip()}\n" for n, v in ordered)
    signed_headers = ";".join(n for n, _ in ordered)
    canon_uri = _canonical_uri(path, service)
    canon_req = f"POST\n{canon_uri}\n\n{canon_headers}\n{signed_headers}\n{body_sha}"
    scope = f"{DATE_STAMP}/{REGION}/{service}/aws4_request"
    sts = (
        "AWS4-HMAC-SHA256\n"
        f"{AMZ_DATE}\n{scope}\n{hashlib.sha256(canon_req.encode()).hexdigest()}"
    )
    signature = _hmac(_signing_key(SECRET, DATE_STAMP, REGION, service), sts).hex()
    auth = (
        f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    block = "".join(f"{n}: {v}\r\n" for n, v in ordered)
    block += f"content-length: {len(body)}\r\n"
    block += f"authorization: {auth}\r\n"
    head = f"POST {_quote_path(path)} HTTP/1.1\r\n{block}Connection: close\r\n\r\n"
    return head.encode("utf-8") + body


# --- the two pinned operation bodies ------------------------------------------


def cloudwatch_put_metric_data_body() -> bytes:
    # PutMetricDataInput: Namespace (str), MetricData (list[MetricDatum]); each
    # MetricDatum in model order with only the present members.
    body = {
        "Namespace": "MyApp/Prod",
        "MetricData": [
            {
                "MetricName": "Latency",
                "Value": 100.0,  # double shape -> 8-byte IEEE-754
                "Unit": "Milliseconds",
                "StorageResolution": 1,  # integer
            },
            {
                "MetricName": "Errors",
                "Value": 0.5,
                "Unit": "Count",
            },
        ],
    }
    return cbor_encode(body)


def translate_translate_text_body() -> bytes:
    body = {
        "Text": "Hello, world",
        "SourceLanguageCode": "en",
        "TargetLanguageCode": "es",
    }
    return cbor_encode(body)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--emit", action="store_true", help="re-pin the golden")
    args = parser.parse_args()

    # 1. The CBOR bodies must equal botocore's output (aws #428 pinned vectors).
    cw_body = cloudwatch_put_metric_data_body()
    tr_body = translate_translate_text_body()
    assert cw_body.hex() == CLOUDWATCH_PUT_METRIC_DATA_BODY_HEX, (
        "CloudWatch PutMetricData CBOR body does not match the botocore-verified "
        f"vector:\n  got      {cw_body.hex()}\n  expected {CLOUDWATCH_PUT_METRIC_DATA_BODY_HEX}"
    )
    assert tr_body.hex() == TRANSLATE_TRANSLATE_TEXT_BODY_HEX, (
        "Translate TranslateText CBOR body does not match the botocore-verified "
        f"vector:\n  got      {tr_body.hex()}\n  expected {TRANSLATE_TRANSLATE_TEXT_BODY_HEX}"
    )
    sys.stderr.write("verify_cbor_requests: CBOR bodies match the botocore vectors\n")

    # 2. The full signed CloudWatch PutMetricData request (SigV4 service
    #    "monitoring", service shape "GraniteServiceVersion20100801").
    request = sign_request(
        service="monitoring",
        host="monitoring.us-east-1.amazonaws.com",
        path="/service/GraniteServiceVersion20100801/operation/PutMetricData",
        body=cw_body,
    )

    if args.emit:
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_bytes(request)
        sys.stderr.write(f"verify_cbor_requests: wrote {GOLDEN.relative_to(REPO_ROOT)}\n")
        return 0

    if not GOLDEN.exists():
        sys.stderr.write(f"verify_cbor_requests: missing golden {GOLDEN}; run --emit\n")
        return 1
    if GOLDEN.read_bytes() != request:
        sys.stderr.write(
            f"verify_cbor_requests: {GOLDEN.relative_to(REPO_ROOT)} does not match the "
            "re-derived request; if intended, re-pin with --emit\n"
        )
        return 1
    sys.stderr.write("verify_cbor_requests: golden matches the independent re-derivation\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
