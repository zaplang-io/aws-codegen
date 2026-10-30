# aws.credentials — the boto3-style credential provider chain (D-0011 §2,
# zaplang-io/aws#341).
#
# aws.core ships the `Credentials` value and the two leaf resolvers the signer
# needs (env + static). This module is the full chain that botocore walks to
# find a usable set of credentials: it tries a fixed sequence of providers and
# returns the first that succeeds, resolving named profiles out of the shared
# INI files, EC2 instance metadata (IMDSv2), the ECS/EKS container endpoint, and
# an external `credential_process`, then caches the result and refreshes it as a
# temporary session nears expiry.
#
# The entry point the SDK calls is `default_credentials()` — it runs the chain
# and hands back a `Credentials` the signer consumes exactly like the static
# `credentials(...)` constructor (which keeps working untouched). Everything the
# chain needs beyond that — env vars, the two INI files, the metadata/container
# HTTP endpoints, the process JSON, and expiry math — rides on the Phase 0
# stdlib (os/fs/process, http with request headers #280/#279, datetime #338).
#
# PROVIDER ORDER (first success wins), matching botocore's default chain:
#   1. Environment variables                    — provider_env
#   2. Shared config/credentials INI + profiles  — provider_shared_config
#        static keys → credential_process → source_profile (basics)
#   3. ECS/EKS container endpoint                — provider_container
#   4. EC2 instance metadata (IMDSv2)            — provider_imds
# The ticket lists IMDS ahead of the container provider; we deliberately keep
# botocore's order (container BEFORE IMDS) because an ECS task runs ON an EC2
# instance whose IMDS is reachable — checking IMDS first would hand back the
# instance role instead of the task role. The `credential_process` and
# `source_profile` providers the ticket enumerates separately are driven by a
# profile, so they resolve inside provider_shared_config (#2). See FRICTION.md.
#
# Every provider is split into a pure parser (INI text, metadata/process JSON,
# a shell command line, expiry comparison) and a thin IO wrapper, so the chain
# ordering and the parsers are all testable offline with fixtured inputs
# (tests/credentials_chain.main.zap). No live AWS calls in the test path.

import core
import os
import fs
import process
import http
import datetime

# ---------------------------------------------------------------------------
# The resolved-credentials record
# ---------------------------------------------------------------------------

# A credential resolution result: the four signer-facing fields (mirroring
# aws.core.Credentials) plus the metadata the chain and the cache need. `ok` is
# whether this provider produced credentials; `expiration` is the ISO-8601
# instant temporary creds expire ("" for non-expiring static/env/ini keys); and
# `provider` names the source for debugging and tests. The signer never sees
# this type — `to_credentials` projects it down to an aws.core.Credentials.
struct CredentialRecord:
    bool ok
    str access_key
    str secret_key
    str session_token
    bool has_session
    str expiration
    str provider

# A found record from explicit fields (`has_session` derived from the token).
def found(
    str access_key,
    str secret_key,
    str session_token,
    str expiration,
    str provider,
) -> CredentialRecord:
    return CredentialRecord(
        ok=True,
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        has_session=len(session_token) > 0,
        expiration=expiration,
        provider=provider,
    )

# A not-found record tagged with the provider that came up empty.
def not_found(str provider) -> CredentialRecord:
    return CredentialRecord(
        ok=False,
        access_key="",
        secret_key="",
        session_token="",
        has_session=False,
        expiration="",
        provider=provider,
    )

# Project a resolved record onto the aws.core.Credentials the signer consumes.
# Delegates to aws.core.credentials so has_session stays derived the one way.
def to_credentials(CredentialRecord rec) -> core.Credentials:
    return core.credentials(rec.access_key, rec.secret_key, rec.session_token)

# ---------------------------------------------------------------------------
# Provider 1 — environment variables
# ---------------------------------------------------------------------------

# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN. This is also the
# Lambda path (the runtime injects these). Both key vars must be present.
def provider_env() -> CredentialRecord:
    if not os.hasenv("AWS_ACCESS_KEY_ID"):
        return not_found("env")
    if not os.hasenv("AWS_SECRET_ACCESS_KEY"):
        return not_found("env")
    auto token = ""
    if os.hasenv("AWS_SESSION_TOKEN"):
        token = os.getenv("AWS_SESSION_TOKEN")
    return found(
        os.getenv("AWS_ACCESS_KEY_ID"),
        os.getenv("AWS_SECRET_ACCESS_KEY"),
        token,
        "",
        "env",
    )

# ---------------------------------------------------------------------------
# Provider 2 — shared config / credentials INI files + named profiles
# ---------------------------------------------------------------------------

# The separator joining a parsed INI "section" and "key" into one dict key. A
# unit-separator (0x1f) never appears in an AWS section/key name.
def ini_sep() -> str:
    return str(chr(31))

# Parse an INI document into a flat dict keyed by `section<US>key` → value.
# Section headers are `[name]`; `#` and `;` start comments; keys are lowercased
# (AWS treats them case-insensitively) while section names (profile names) keep
# their case. Keys outside any section, blank lines and comments are skipped.
def parse_ini(str text) -> dict[str, str]:
    dict[str, str] out = {}
    auto section = ""
    for raw in text.split("\n"):
        auto line = raw.strip()
        if len(line) == 0:
            continue
        if line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:len(line) - 1].strip()
            continue
        auto eq = line.find("=")
        if eq < 0:
            continue
        if len(section) == 0:
            continue
        auto key = line[0:eq].strip().lower()
        auto val = line[eq + 1:len(line)].strip()
        out[section + ini_sep() + key] = val
    return out

# Look up one key in a parsed INI, by section and (already-lowercase) key name.
def ini_get(dict[str, str] ini, str section, str key) -> Optional[str]:
    return ini.get(section + ini_sep() + key)

# Look a key up in the credentials INI first (it wins), then the config INI. The
# credentials file addresses a profile by its bare name (`[name]`); the config
# file uses `[profile name]` (and `[default]` for the default profile), so the
# two section spellings are passed in separately.
def ini_get_either(
    str cred_section,
    str cfg_section,
    dict[str, str] cred_ini,
    dict[str, str] cfg_ini,
    str key,
) -> Optional[str]:
    Optional[str] v = ini_get(cred_ini, cred_section, key)
    if v.is_some():
        return v
    return ini_get(cfg_ini, cfg_section, key)

# Resolve a named profile out of the two already-parsed INIs. Precedence inside
# a profile mirrors botocore: explicit static keys, then `credential_process`,
# then a `source_profile`/`role_arn` pair. The pure core of provider #2 — tests
# drive it with fixtured INI text, no files touched.
def resolve_profile(
    str profile,
    dict[str, str] cred_ini,
    dict[str, str] cfg_ini,
) -> CredentialRecord:
    return resolve_profile_depth(profile, cred_ini, cfg_ini, 0)

# `resolve_profile` with a recursion guard, so a cyclic `source_profile` chain
# terminates instead of looping forever.
def resolve_profile_depth(
    str profile,
    dict[str, str] cred_ini,
    dict[str, str] cfg_ini,
    int64 depth,
) -> CredentialRecord:
    if depth > 8:
        return not_found("shared-config")
    auto cred_section = profile
    auto cfg_section = profile
    if profile != "default":
        cfg_section = "profile " + profile

    Optional[str] ak = ini_get_either(
        cred_section,
        cfg_section,
        cred_ini,
        cfg_ini,
        "aws_access_key_id",
    )
    Optional[str] sk = ini_get_either(
        cred_section,
        cfg_section,
        cred_ini,
        cfg_ini,
        "aws_secret_access_key",
    )
    if ak.is_some() and sk.is_some():
        Optional[str] st = ini_get_either(
            cred_section,
            cfg_section,
            cred_ini,
            cfg_ini,
            "aws_session_token",
        )
        return found(ak.unwrap(), sk.unwrap(), st.unwrap_or(""), "", "shared-config")

    Optional[str] cp = ini_get_either(
        cred_section,
        cfg_section,
        cred_ini,
        cfg_ini,
        "credential_process",
    )
    if cp.is_some():
        return run_process_credentials(cp.unwrap())

    Optional[str] src = ini_get_either(
        cred_section,
        cfg_section,
        cred_ini,
        cfg_ini,
        "source_profile",
    )
    Optional[str] role = ini_get_either(
        cred_section,
        cfg_section,
        cred_ini,
        cfg_ini,
        "role_arn",
    )
    if src.is_some() and role.is_some():
        # source_profile basics: resolve the SOURCE profile's base credentials.
        # Performing the STS AssumeRole with them (to mint creds for `role_arn`)
        # is deferred until the SDK grows an STS client; the base creds are
        # surfaced so the chain still yields something usable. See FRICTION.md.
        auto base = resolve_profile_depth(src.unwrap(), cred_ini, cfg_ini, depth + 1)
        if base.ok:
            return found(
                base.access_key,
                base.secret_key,
                base.session_token,
                base.expiration,
                "shared-config/source_profile",
            )
        return base

    return not_found("shared-config")

# The home directory, honoring HOME (POSIX) then USERPROFILE (Windows).
def home_dir() -> str:
    if os.hasenv("HOME"):
        return os.getenv("HOME")
    if os.hasenv("USERPROFILE"):
        return os.getenv("USERPROFILE")
    return ""

# The shared credentials-file path: $AWS_SHARED_CREDENTIALS_FILE or ~/.aws/credentials.
def credentials_file_path() -> str:
    auto p = os.getenv("AWS_SHARED_CREDENTIALS_FILE")
    if len(p) > 0:
        return p
    return home_dir() + "/.aws/credentials"

# The shared config-file path: $AWS_CONFIG_FILE or ~/.aws/config.
def config_file_path() -> str:
    auto p = os.getenv("AWS_CONFIG_FILE")
    if len(p) > 0:
        return p
    return home_dir() + "/.aws/config"

# The active profile name: $AWS_PROFILE (or the legacy $AWS_DEFAULT_PROFILE),
# else "default".
def active_profile() -> str:
    if os.hasenv("AWS_PROFILE"):
        return os.getenv("AWS_PROFILE")
    if os.hasenv("AWS_DEFAULT_PROFILE"):
        return os.getenv("AWS_DEFAULT_PROFILE")
    return "default"

# Provider #2: read the two shared INI files (when present) and resolve the
# active profile out of them.
def provider_shared_config() -> CredentialRecord:
    dict[str, str] cred_ini = {}
    auto cred_path = credentials_file_path()
    if fs.exists(cred_path):
        cred_ini = parse_ini(fs.read_file(cred_path))
    dict[str, str] cfg_ini = {}
    auto cfg_path = config_file_path()
    if fs.exists(cfg_path):
        cfg_ini = parse_ini(fs.read_file(cfg_path))
    return resolve_profile(active_profile(), cred_ini, cfg_ini)

# ---------------------------------------------------------------------------
# Shared metadata/process JSON credential parser
# ---------------------------------------------------------------------------

# Parse a credential JSON object (IMDS, the container endpoint and
# `credential_process` all return the same shape) into a record. `token_field`
# is "Token" for the metadata/container endpoints and "SessionToken" for a
# process. Uses aws.core.json_string_field (best-effort, no full JSON parse —
# enough for these flat, server-produced objects). Missing access/secret keys
# make it not-found.
def parse_json_credentials(str body, str token_field, str provider) -> CredentialRecord:
    Optional[str] ak = core.json_string_field(body, "AccessKeyId")
    Optional[str] sk = core.json_string_field(body, "SecretAccessKey")
    if ak.is_none() or sk.is_none():
        return not_found(provider)
    Optional[str] tok = core.json_string_field(body, token_field)
    Optional[str] exp = core.json_string_field(body, "Expiration")
    return found(
        ak.unwrap(),
        sk.unwrap(),
        tok.unwrap_or(""),
        exp.unwrap_or(""),
        provider,
    )

# ---------------------------------------------------------------------------
# Provider: external credential_process
# ---------------------------------------------------------------------------

# Split a command line into argv on spaces, honoring double-quoted runs so a
# path with a space survives (e.g. `"/opt/my tools/creds" --json`). A minimal
# shlex; single quotes and backslash escapes are not interpreted (documented).
def shell_split(str s) -> list[str]:
    list[str] out = []
    auto cur = ""
    auto in_quote = False
    auto have = False
    for i in range(0, len(s)):
        auto c = s[i:i + 1]
        if c == "\"":
            in_quote = not in_quote
            have = True
            continue
        if c == " " and not in_quote:
            if have:
                out.append(cur)
                cur = ""
                have = False
            continue
        cur = cur + c
        have = True
    if have:
        out.append(cur)
    return out

# Parse `credential_process` stdout: the documented JSON with Version 1,
# AccessKeyId, SecretAccessKey, SessionToken and an optional Expiration.
def parse_process_credentials(str body) -> CredentialRecord:
    return parse_json_credentials(body, "SessionToken", "process")

# Run a `credential_process` command and parse its stdout. A non-zero exit or an
# empty command line is not-found.
def run_process_credentials(str command) -> CredentialRecord:
    auto argv = shell_split(command)
    if len(argv) == 0:
        return not_found("process")
    auto code, out, err = process.run(argv)
    if code != 0:
        return not_found("process")
    return parse_process_credentials(out)

# ---------------------------------------------------------------------------
# Provider 3 — ECS/EKS container credentials endpoint
# ---------------------------------------------------------------------------

# The container-credentials authorization header value: the literal
# $AWS_CONTAINER_AUTHORIZATION_TOKEN, else the contents of the file named by
# $AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE (EKS pod identity), else "".
def container_auth_token() -> str:
    if os.hasenv("AWS_CONTAINER_AUTHORIZATION_TOKEN"):
        return os.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")
    if os.hasenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"):
        auto f = os.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
        if fs.exists(f):
            return fs.read_file(f).strip()
    return ""

# The container-credentials URI from the environment: the full URI
# ($AWS_CONTAINER_CREDENTIALS_FULL_URI) wins, else the relative URI
# ($AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) under the link-local ECS agent host
# http://169.254.170.2. "" when neither is set (the provider is inactive).
def container_uri() -> str:
    auto rel = os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    auto full = os.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
    if len(full) > 0:
        return full
    if len(rel) > 0:
        return "http://169.254.170.2" + rel
    return ""

# Provider #3: GET the container endpoint (with the auth header when present)
# and parse its credential JSON. Inactive (not-found) when no URI is configured.
def provider_container() -> CredentialRecord:
    auto uri = container_uri()
    if len(uri) == 0:
        return not_found("container")
    dict[str, str] h = {}
    auto auth = container_auth_token()
    if len(auth) > 0:
        h["Authorization"] = auth
    auto resp = http.get(uri, h)
    if http.status(resp) != 200:
        return not_found("container")
    return parse_json_credentials(http.body(resp), "Token", "container")

# ---------------------------------------------------------------------------
# Provider 4 — EC2 instance metadata (IMDSv2, token-based)
# ---------------------------------------------------------------------------

# The IMDS base URL: $AWS_EC2_METADATA_SERVICE_ENDPOINT, else the link-local
# http://169.254.169.254.
def imds_endpoint() -> str:
    auto e = os.getenv("AWS_EC2_METADATA_SERVICE_ENDPOINT")
    if len(e) > 0:
        return e
    return "http://169.254.169.254"

# Whether IMDS is turned off via $AWS_EC2_METADATA_DISABLED=true.
def imds_disabled() -> bool:
    if not os.hasenv("AWS_EC2_METADATA_DISABLED"):
        return False
    return os.getenv("AWS_EC2_METADATA_DISABLED").lower() == "true"

# Provider #4: the IMDSv2 handshake — PUT a short-lived session token, then GET
# the instance role name and finally its credentials, carrying the token on
# every GET. Any non-200 (including no IMDS present) is not-found. IMDSv1
# (token-less) is intentionally not attempted — v2 is the secure default.
def provider_imds() -> CredentialRecord:
    if imds_disabled():
        return not_found("imds")
    auto base = imds_endpoint()

    dict[str, str] token_hdr = {}
    token_hdr["X-aws-ec2-metadata-token-ttl-seconds"] = "21600"
    auto tr = http.request("PUT", base + "/latest/api/token", "", token_hdr)
    if http.status(tr) != 200:
        return not_found("imds")
    auto token = http.body(tr).strip()

    dict[str, str] h = {}
    h["X-aws-ec2-metadata-token"] = token
    auto role_resp = http.get(base + "/latest/meta-data/iam/security-credentials/", h)
    if http.status(role_resp) != 200:
        return not_found("imds")
    auto role = http.body(role_resp).strip()
    if len(role) == 0:
        return not_found("imds")

    auto cred_resp = http.get(
        base + "/latest/meta-data/iam/security-credentials/" + role,
        h,
    )
    if http.status(cred_resp) != 200:
        return not_found("imds")
    return parse_json_credentials(http.body(cred_resp), "Token", "imds")

# ---------------------------------------------------------------------------
# The chain
# ---------------------------------------------------------------------------

# Return the first record in `candidates` whose resolution succeeded, else a
# not-found. The pure selector the chain is built on — tests pin ordering by
# handing it fixtured records.
def first_ok(list[CredentialRecord] candidates) -> CredentialRecord:
    for c in candidates:
        if c.ok:
            return c
    return not_found("chain")

# Walk the default provider chain and return the first provider that resolves
# credentials (see PROVIDER ORDER in the module header). Not-found "chain" when
# every provider comes up empty.
def resolve_credential_record() -> CredentialRecord:
    auto env = provider_env()
    if env.ok:
        return env
    auto prof = provider_shared_config()
    if prof.ok:
        return prof
    auto cont = provider_container()
    if cont.ok:
        return cont
    auto imds = provider_imds()
    if imds.ok:
        return imds
    return not_found("chain")

# THE entry point: run the chain and project the result onto an
# aws.core.Credentials for the signer. On total failure this yields empty-string
# keys (same contract as aws.core.credentials_from_env on a missing env), so the
# caller can detect it by an empty access_key without a thrown error.
def default_credentials() -> core.Credentials:
    return to_credentials(resolve_credential_record())

# ---------------------------------------------------------------------------
# Caching + refresh (datetime-driven expiry)
# ---------------------------------------------------------------------------

# A cached resolution plus the refresh window. `record` is the last resolved
# record; `skew_seconds` is how far ahead of `record.expiration` the cache
# treats temporary creds as stale (botocore refreshes ~5–15 min early). The
# cache is an explicit value the caller threads through (there is no mutable
# module singleton), which also keeps the refresh logic pure and testable.
struct CredentialCache:
    CredentialRecord record
    int64 skew_seconds

# An empty cache with a refresh window.
def new_cache(int64 skew_seconds) -> CredentialCache:
    return CredentialCache(record=not_found("uninitialized"), skew_seconds=skew_seconds)

# An empty cache with the default 5-minute refresh window.
def default_cache() -> CredentialCache:
    return new_cache(300)

# The epoch seconds for an AWS ISO-8601 Expiration (e.g. "2026-01-01T00:00:00Z").
# datetime.strptime is lenient and consumes a trailing zone, so the common
# "...Z" and "...+00:00" forms both parse as naive UTC.
def expiration_epoch(str iso) -> int64:
    auto dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
    return datetime.to_timestamp(dt)

# The current UTC time in epoch seconds (what the cache compares expiry against).
def now_epoch() -> int64:
    return datetime.to_timestamp(datetime.now())

# Whether a cached record is still usable at `now`. A not-found record is never
# fresh; a record with no expiration (static/env/ini keys) is always fresh; a
# temporary record is fresh until it is within `skew_seconds` of expiring.
def cache_is_fresh(CredentialCache c, int64 now) -> bool:
    if not c.record.ok:
        return False
    if len(c.record.expiration) == 0:
        return True
    return now + c.skew_seconds < expiration_epoch(c.record.expiration)

# Store a freshly resolved record in the cache (keeping the refresh window).
def cache_store(CredentialCache c, CredentialRecord r) -> CredentialCache:
    return CredentialCache(record=r, skew_seconds=c.skew_seconds)

# Return a cache whose record is fresh at `now`: the input unchanged when it is
# still fresh, else one holding a re-resolved record from the chain. The caller
# keeps the returned cache and reads `.record` off it.
def cache_refresh(CredentialCache c, int64 now) -> CredentialCache:
    if cache_is_fresh(c, now):
        return c
    return cache_store(c, resolve_credential_record())

# Convenience: refresh against the current time.
def cache_refresh_now(CredentialCache c) -> CredentialCache:
    return cache_refresh(c, now_epoch())
