# aws.dynamodb — DynamoDB client (awsJson 1.0 protocol).
#
# Depends on aws.core and aws.awsjson (bundled ahead of this file; see FRICTION.md
# #1 on why there is no `import aws.core` yet). DynamoDB is the cleanest service
# for the hand-written vertical: the awsJson protocol puts everything in the body,
# the path is always "/", there is no query string, and the signed header set is
# small.
#
# Every operation now rides the aws.awsjson codec (zaplang-io/zap#344): the client
# builds the JSON body, then hands it to `awsjson_request`, which stamps the
# Content-Type + X-Amz-Target, posts to "/", and SigV4-signs via aws.core. The
# target prefix / content-type / signing that used to be duplicated here are the
# codec's job now.
#
# Two body styles coexist because `@derive(Json)` does not model dynamic-key maps
# yet (collections in derive are a follow-up to #346):
#   * Item/key operations (get_item, put_item) build the AttributeValue map by
#     hand from `dict[str, str]` inputs — attribute names emitted in sorted order
#     so the wire body is deterministic; numeric ("N") attributes come as a second
#     dict. JSON string values must still not contain characters needing JSON
#     escaping (no escaping pass on the hand path); numbers are decimal digits.
#   * Flat/nested operations (describe_table) use `@derive(Json)` end to end: the
#     input shape serializes with `.to_json()` and the output parses with
#     `Output.from_json(resp.body)` — the codec's intended request/response path.

# The DynamoDB awsJson protocol: version 1.0, API id "DynamoDB_20120810".
import awsjson
import core
import endpoints

def ddb_protocol() -> awsjson.AwsJson:
    return awsjson.awsjson_1_0("DynamoDB_20120810", "dynamodb")

# --- AttributeValue JSON (built from dicts) --------------------------------

# One `"name":{"S":"value"}` string-attribute fragment.
def ddb_attr_s(str name, str value) -> str:
    return "\"" + name + "\":{\"S\":\"" + value + "\"}"

# One `"name":{"N":"value"}` number-attribute fragment (value is the decimal
# digits).
def ddb_attr_n(str name, str value) -> str:
    return "\"" + name + "\":{\"N\":\"" + value + "\"}"

# Render an attribute map as the comma-joined body of a JSON object (no
# surrounding braces): string attributes from `strings`, number attributes from
# `numbers`. Names across both maps are emitted in a single sorted order, so the
# output is deterministic. A name present in both maps is emitted as its string
# form (callers should not overload a name across types).
def ddb_attributes(dict[str, str] strings, dict[str, str] numbers) -> str:
    list[str] names = []
    for k in strings.keys():
        names.append(k)
    for k in numbers.keys():
        if not k in strings:
            names.append(k)
    auto out = ""
    auto first = True
    for name in sorted(names):
        auto frag = ""
        if name in strings:
            Optional[str] sv = strings.get(name)
            frag = ddb_attr_s(name, sv.unwrap_or(""))
        else:
            Optional[str] nv = numbers.get(name)
            frag = ddb_attr_n(name, nv.unwrap_or(""))
        if first:
            out = frag
            first = False
        else:
            out = out + "," + frag
    return out

# GetItem body: {"TableName":"T","Key":{<key attrs>}}.
def get_item_body(str table, dict[str, str] key) -> str:
    dict[str, str] no_numbers = {}
    return "{\"TableName\":\"" + table + "\",\"Key\":{" + ddb_attributes(key, no_numbers) + "}}"

# PutItem body: {"TableName":"T","Item":{<item attrs>}}.
def put_item_body(str table, dict[str, str] strings, dict[str, str] numbers) -> str:
    return "{\"TableName\":\"" + table + "\",\"Item\":{" + ddb_attributes(strings, numbers) + "}}"

# --- DescribeTable (the @derive(Json) request/response path) ----------------

# DescribeTable input — a flat shape, so it serializes straight through
# `@derive(Json)`: `DescribeTableInput(TableName="Users").to_json()` is exactly
# the awsJson body `{"TableName":"Users"}`.
@derive(Json)
struct DescribeTableInput:
    str TableName

# The subset of DynamoDB's TableDescription we surface. All Optional, so a
# response that omits any of them still decodes; `@derive(Json)` ignores the many
# keys we do not model (KeySchema, ProvisionedThroughput, ...).
@derive(Json)
struct TableDescription:
    Optional[str] TableName
    Optional[str] TableStatus
    Optional[int64] ItemCount

# DescribeTable output: the service wraps the description in a "Table" object.
# Parsed with `DescribeTableOutput.from_json(resp.body)`.
@derive(Json)
struct DescribeTableOutput:
    TableDescription Table

# --- operations ------------------------------------------------------------

# GetItem. `key` is the primary key as an attribute map, e.g. {"id": "alice"}
# (reads like boto3's `Key=...`). Returns ready-to-send HTTP/1.1 request text,
# built + signed through the aws.awsjson codec.
def get_item_request(
    core.Credentials creds,
    str region,
    str table,
    dict[str, str] key,
    str amz_date,
    str date_stamp,
) -> str:
    auto host = endpoints.regional_host("dynamodb", region)
    auto body = get_item_body(table, key)
    return awsjson.awsjson_request(
        ddb_protocol(),
        creds,
        region,
        host,
        "GetItem",
        body,
        amz_date,
        date_stamp,
    )

# PutItem. `item` is the string attributes as a map (e.g. {"id": "alice",
# "name": "Alice"}); pass `numbers` for numeric ("N") attributes
# (e.g. {"age": "30"}). Returns ready-to-send HTTP/1.1 request text, built +
# signed through the aws.awsjson codec.
def put_item_request(
    core.Credentials creds,
    str region,
    str table,
    dict[str, str] item,
    str amz_date,
    str date_stamp,
    dict[str, str] numbers = {},
) -> str:
    auto host = endpoints.regional_host("dynamodb", region)
    auto body = put_item_body(table, item, numbers)
    return awsjson.awsjson_request(
        ddb_protocol(),
        creds,
        region,
        host,
        "PutItem",
        body,
        amz_date,
        date_stamp,
    )

# DescribeTable. The input shape is serialized with `@derive(Json)` and the
# request goes through the same codec as the item operations. Returns
# ready-to-send HTTP/1.1 request text; parse a reply with
# `DescribeTableOutput.from_json(response.body)`.
def describe_table_request(
    core.Credentials creds,
    str region,
    str table,
    str amz_date,
    str date_stamp,
) -> str:
    auto host = endpoints.regional_host("dynamodb", region)
    auto body = DescribeTableInput(TableName=table).to_json()
    return awsjson.awsjson_request(
        ddb_protocol(),
        creds,
        region,
        host,
        "DescribeTable",
        body,
        amz_date,
        date_stamp,
    )
