# aws.endpoints — structured region + endpoint resolution (D-0011 §6, #342).
#
# Depends on aws.core (bundled ahead of this file; it uses core's `Endpoint`
# struct and is used BY core's endpoint shims, so the two are always bundled
# together — see tools/run-tests.sh / ci.yml). This module turns the v1 template
# seams (regional_host / s3_virtual_host) into a proper resolver with the pieces
# botocore's endpoint layer carries:
#
#   * partition awareness (aws / aws-cn / aws-us-gov), so the DNS suffix is not
#     hard-coded to amazonaws.com;
#   * the standard templated service host {service}.{region}.{dnsSuffix}, with
#     the FIPS and dualstack knobs that mutate it;
#   * S3 addressing: virtual-hosted vs path style chosen by a flag or the
#     bucket name's DNS-compatibility, the S3-specific dualstack label, and the
#     us-east-1 legacy global-endpoint quirk.
#
# It is deliberately shaped so the full AWS endpoint-ruleset JSON (#342
# follow-up) can replace the bodies here without reshaping callers: callers hand
# in (service, region, options) and read back a host (and, for S3, whether the
# bucket is in the path). The old core function names stay as thin shims over
# this module, so existing call sites keep working.
#
# Partitions beyond the three above (aws-iso / aws-iso-b) are intentionally out
# of scope for v1 and fall through to the aws partition; the ruleset import will
# complete them.

# ---------------------------------------------------------------------------
# Partitions
# ---------------------------------------------------------------------------

# An AWS partition: its id, the normal DNS suffix for hosts in it, and the
# dualstack DNS suffix used by the generic (non-S3) dualstack template. S3 does
# NOT use `dualstack_dns_suffix` — it expresses dualstack with a `.dualstack`
# label on the base suffix (see `s3_service_label`).
struct Partition:
    str id
    str dns_suffix
    str dualstack_dns_suffix

# The main commercial partition.
def partition_aws() -> Partition:
    return Partition(
        id="aws",
        dns_suffix="amazonaws.com",
        dualstack_dns_suffix="api.aws",
    )

# The China partition (ICP-isolated), suffix amazonaws.com.cn.
def partition_aws_cn() -> Partition:
    return Partition(
        id="aws-cn",
        dns_suffix="amazonaws.com.cn",
        dualstack_dns_suffix="api.amazonwebservices.com.cn",
    )

# The GovCloud (US) partition, suffix amazonaws.com.
def partition_aws_us_gov() -> Partition:
    return Partition(
        id="aws-us-gov",
        dns_suffix="amazonaws.com",
        dualstack_dns_suffix="api.aws",
    )

# The partition a region belongs to, by the region-name prefix the real ruleset
# keys on: "cn-*" → aws-cn, "us-gov-*" → aws-us-gov, everything else → aws.
def partition_for_region(str region) -> Partition:
    if region.startswith("cn-"):
        return partition_aws_cn()
    if region.startswith("us-gov-"):
        return partition_aws_us_gov()
    return partition_aws()

# ---------------------------------------------------------------------------
# Generic service resolution options + host template
# ---------------------------------------------------------------------------

# Resolution knobs shared by every service. `use_fips` selects the FIPS 140
# endpoints; `use_dualstack` selects the IPv4/IPv6 dualstack endpoints.
struct ResolveOptions:
    bool use_dualstack
    bool use_fips

# Options constructor with boto3-style keyword defaults (both knobs off).
def resolve_options(
    bool use_dualstack = False,
    bool use_fips = False,
) -> ResolveOptions:
    return ResolveOptions(use_dualstack=use_dualstack, use_fips=use_fips)

# The default options: no dualstack, no FIPS (the plain regional endpoint).
def default_options() -> ResolveOptions:
    return ResolveOptions(use_dualstack=False, use_fips=False)

# The DNS suffix a generic host uses under these options: the dualstack suffix
# when dualstack is requested, else the partition's normal suffix.
def endpoint_dns_suffix(Partition p, ResolveOptions opts) -> str:
    if opts.use_dualstack:
        return p.dualstack_dns_suffix
    return p.dns_suffix

# The service label for a generic host: the service name, with "-fips" appended
# when FIPS is requested (the common {service}-fips template).
def service_label(str service, ResolveOptions opts) -> str:
    if opts.use_fips:
        return service + "-fips"
    return service

# The host for a regional service under options:
#   {service}[-fips].{region}.{dnsSuffix|dualStackDnsSuffix}
# e.g. ("dynamodb","us-east-1",default)              -> dynamodb.us-east-1.amazonaws.com
#      ("dynamodb","us-east-1",fips)                 -> dynamodb-fips.us-east-1.amazonaws.com
#      ("dynamodb","us-east-1",dualstack)            -> dynamodb.us-east-1.api.aws
#      ("ec2","cn-north-1",default)                  -> ec2.cn-north-1.amazonaws.com.cn
def resolve_service_host(str service, str region, ResolveOptions opts) -> str:
    auto p = partition_for_region(region)
    return service_label(service, opts) + "." + region + "." + endpoint_dns_suffix(p, opts)

# The resolved `Endpoint` (core's struct) for a regional service.
def resolve_service_endpoint(str service, str region, ResolveOptions opts) -> Endpoint:
    return Endpoint(
        host=resolve_service_host(service, region, opts),
        region=region,
        service=service,
    )

# ---------------------------------------------------------------------------
# S3 addressing
# ---------------------------------------------------------------------------

# A resolved S3 endpoint. `path_style` is True when the bucket could not be (or
# was asked not to be) placed in the host, so callers must prefix it into the
# request path instead; when False the bucket is already the first host label.
struct S3Endpoint:
    str host
    str region
    bool path_style

# S3 addressing options. `force_path_style` forces path addressing regardless of
# the bucket name; `use_global_endpoint` selects the legacy region-less
# us-east-1 endpoint (bucket.s3.amazonaws.com / s3.amazonaws.com).
struct S3Options:
    bool use_dualstack
    bool use_fips
    bool force_path_style
    bool use_global_endpoint

# S3 options constructor with keyword defaults (everything off = modern regional
# virtual-hosted addressing).
def s3_options(
    bool use_dualstack = False,
    bool use_fips = False,
    bool force_path_style = False,
    bool use_global_endpoint = False,
) -> S3Options:
    return S3Options(
        use_dualstack=use_dualstack,
        use_fips=use_fips,
        force_path_style=force_path_style,
        use_global_endpoint=use_global_endpoint,
    )

# The default S3 options (modern regional virtual-hosted addressing).
def default_s3_options() -> S3Options:
    return S3Options(
        use_dualstack=False,
        use_fips=False,
        force_path_style=False,
        use_global_endpoint=False,
    )

# The S3 service label: "s3", with "-fips" for FIPS and a ".dualstack" label for
# dualstack. Unlike generic services, S3 dualstack stays on the BASE DNS suffix
# (s3.dualstack.{region}.amazonaws.com), so the label — not the suffix — carries
# it. Examples: "s3", "s3-fips", "s3.dualstack", "s3-fips.dualstack".
def s3_service_label(S3Options opts) -> str:
    auto lbl = "s3"
    if opts.use_fips:
        lbl = "s3-fips"
    if opts.use_dualstack:
        lbl = lbl + ".dualstack"
    return lbl

# Whether to use the legacy region-less global S3 endpoint. Only us-east-1 ever
# had one, and FIPS/dualstack always regionalize, so the quirk applies only with
# neither knob set.
def s3_is_global(str region, S3Options opts) -> bool:
    if opts.use_fips:
        return False
    if opts.use_dualstack:
        return False
    return opts.use_global_endpoint and region == "us-east-1"

# The host part shared by virtual-hosted and path-style S3 (everything after any
# bucket label): "<label>.<region>.<dnsSuffix>", or "<label>.<dnsSuffix>" for
# the global endpoint.
def s3_host_suffix(str region, S3Options opts, Partition p) -> str:
    auto label = s3_service_label(opts)
    if s3_is_global(region, opts):
        return label + "." + p.dns_suffix
    return label + "." + region + "." + p.dns_suffix

# Whether `cp` is a legal S3 virtual-host DNS label character: lowercase letter,
# digit, or hyphen.
def is_s3_label_cp(int64 cp) -> bool:
    if cp >= 97 and cp <= 122:
        return True
    if cp >= 48 and cp <= 57:
        return True
    return cp == 45

# Whether `cp` is alphanumeric (lowercase letter or digit) — the requirement for
# the first and last label characters.
def is_s3_alnum_cp(int64 cp) -> bool:
    if cp >= 97 and cp <= 122:
        return True
    return cp >= 48 and cp <= 57

# Whether `bucket` can be virtual-hosted over HTTPS: 3–63 chars, only lowercase
# letters/digits/hyphens, first and last alphanumeric, and NO dot. (A dotted
# bucket is DNS-valid but breaks the S3 wildcard TLS certificate over HTTPS, so
# botocore falls back to path style — and this SDK is always HTTPS.) An
# unhostable bucket is served path-style.
def is_virtual_hostable(str bucket) -> bool:
    auto n = len(bucket)
    if n < 3:
        return False
    if n > 63:
        return False
    if bucket.contains("."):
        return False
    for c in bucket:
        if not is_s3_label_cp(ord(c)):
            return False
    if not is_s3_alnum_cp(ord(bucket[0])):
        return False
    if not is_s3_alnum_cp(ord(bucket[n - 1])):
        return False
    return True

# Resolve an S3 endpoint for a bucket. Virtual-hosted when the bucket is
# hostable and path style is not forced; otherwise path style (bucket goes in
# the request path). Honors FIPS, dualstack, the us-east-1 global quirk, and the
# region's partition.
def resolve_s3(str bucket, str region, S3Options opts) -> S3Endpoint:
    auto p = partition_for_region(region)
    auto suffix = s3_host_suffix(region, opts, p)
    auto path_style = opts.force_path_style or not is_virtual_hostable(bucket)
    if path_style:
        return S3Endpoint(host=suffix, region=region, path_style=True)
    return S3Endpoint(host=bucket + "." + suffix, region=region, path_style=False)

# The virtual-hosted S3 host string for a bucket under options (no path-style
# fallback — always bucket-in-host). Backs core's `s3_virtual_host` shim.
def s3_virtual_host_for(str bucket, str region, S3Options opts) -> str:
    auto p = partition_for_region(region)
    return bucket + "." + s3_host_suffix(region, opts, p)

# The service-level / path-style S3 host for a region under options (no bucket
# label). Backs s3.zap's `s3_regional_host` shim.
def s3_service_host(str region, S3Options opts) -> str:
    auto p = partition_for_region(region)
    return s3_host_suffix(region, opts, p)

# The request-path prefix for an S3 endpoint: "/<bucket>" when the bucket is in
# the path (path-style), else "" (the bucket is in the host). Callers append the
# key path to this.
def s3_path_prefix(S3Endpoint ep, str bucket) -> str:
    if ep.path_style:
        return "/" + bucket
    return ""
