# aws.retry — AWS "standard" retry mode for the Zap AWS SDK.
#
# This module fills the retry seam the aws.core skeleton left as a baseline
# (D-0011 §7). It is bundled AFTER aws.core (see FRICTION.md #1 — the compiler
# does not yet link Zap-to-Zap imports, so a runnable program is the library
# modules + one main() concatenated), so every type it leans on — `Response`,
# `AwsError`, `Request`, `Credentials`, `is_success`, `parse_error`,
# `sign_request_now`, `send` — is already in scope from aws.core.
#
# It mirrors botocore's `standard` retry mode, the mode the modern AWS SDKs
# default to:
#   1. Error classification — a response is retryable when it is a throttling
#      error (by AWS error code or HTTP 429), a transient server error (HTTP
#      500/502/503/504, or a connection error modeled as status 0), or a
#      transient error code; every other 4xx is permanent and is surfaced
#      immediately.
#   2. Exponential backoff with full jitter — the wait before retry N (0-based)
#      is a uniform random draw in [0, min(max_backoff, base * 2**N)]. The jitter
#      source is the stdlib `random` RNG (zaplang-io/zap#98), which `seed_jitter`
#      makes deterministic so the tests can pin behavior.
#   3. A retry-quota token bucket — a per-client balance that each retry draws
#      down and each success refills, so a sustained storm of failures runs the
#      bucket dry and retries stop (exactly botocore's defense against retry
#      amplification).
#   4. A retry loop seam — `retry_send` wraps a caller-supplied "sign + send"
#      attempt (`fn() -> Response`): it runs the attempt, classifies the result,
#      and on a retryable result waits the backoff and re-attempts while attempts
#      and quota remain. `send_request_with_retry` is the convenience that builds
#      the live attempt closure (re-signing with a fresh SigV4 timestamp every
#      try) around an aws.core `Request`.
#
# Callers that do NOT want retries keep using aws.core `send` / `send_https`
# directly — nothing here is on that path unless you route through it.

import core
import random
import math
import time

# ---------------------------------------------------------------------------
# Tunables (botocore `standard`-mode defaults)
# ---------------------------------------------------------------------------

# Retry configuration. `max_attempts` is the TOTAL number of tries (botocore's
# `max_attempts=3` → the first call plus up to two retries). `base_delay` and
# `max_backoff` are seconds and shape the full-jitter backoff. The token costs
# model botocore's RetryQuota: a retry on an HTTP error draws `retry_cost`
# tokens, a retry on a connection error (status 0) draws the larger
# `timeout_retry_cost`, and a clean first-try success refills `no_retry_refill`.
struct RetryConfig:
    int64 max_attempts
    float64 base_delay
    float64 max_backoff
    int64 retry_cost
    int64 timeout_retry_cost
    int64 no_retry_refill

# The standard-mode defaults: 3 total attempts, 1s base, 20s cap, botocore's
# 5/10/1 token economics.
def standard_retry_config() -> RetryConfig:
    return RetryConfig(
        max_attempts=3,
        base_delay=1.0,
        max_backoff=20.0,
        retry_cost=5,
        timeout_retry_cost=10,
        no_retry_refill=1,
    )

# A config that never retries (one attempt), for callers that want standard
# classification/plumbing but no re-tries.
def no_retry_config() -> RetryConfig:
    return RetryConfig(
        max_attempts=1,
        base_delay=0.0,
        max_backoff=0.0,
        retry_cost=5,
        timeout_retry_cost=10,
        no_retry_refill=1,
    )

# The default token-bucket capacity (botocore `DEFAULT_MAX_CAPACITY`).
def default_quota_capacity() -> int64:
    return 500

# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------

# Retry classes returned by `retry_class`: a request is either not retryable, a
# transient failure, or a throttling failure. Throttling and transient are both
# retryable; they are distinguished because a connection/transient timeout draws
# more quota than an ordinary throttle (see `retry_cost` vs `timeout_retry_cost`)
# and because callers may want to surface throttling distinctly.
def class_none() -> int64:
    return 0

def class_transient() -> int64:
    return 1

def class_throttling() -> int64:
    return 2

# The AWS error codes that mean "you are being throttled" across services. This
# is the ticket's set (Throttling, ThrottlingException, TooManyRequests,
# RequestLimitExceeded) widened to the rest of botocore's
# `_THROTTLED_ERROR_CODES` so any service's throttle is recognized.
def is_throttling_code(str code) -> bool:
    if code == "Throttling":
        return True
    if code == "ThrottlingException":
        return True
    if code == "ThrottledException":
        return True
    if code == "TooManyRequests":
        return True
    if code == "TooManyRequestsException":
        return True
    if code == "RequestThrottled":
        return True
    if code == "RequestThrottledException":
        return True
    if code == "RequestLimitExceeded":
        return True
    if code == "BandwidthLimitExceeded":
        return True
    if code == "ProvisionedThroughputExceededException":
        return True
    if code == "EC2ThrottledException":
        return True
    if code == "SlowDown":
        return True
    return False

# AWS error codes that mean "transient, retry" without being throttles
# (botocore's `_TRANSIENT_ERROR_CODES`). These arrive on assorted statuses, so
# they are classified by code regardless of the HTTP status.
def is_transient_code(str code) -> bool:
    if code == "RequestTimeout":
        return True
    if code == "RequestTimeoutException":
        return True
    if code == "PriorRequestNotComplete":
        return True
    if code == "IDPCommunicationError":
        return True
    return False

# Whether an HTTP status is a retryable transient server error: the 5xx set AWS
# marks retryable (500/502/503/504) plus status 0, the sentinel this module uses
# for a connection-level failure (no HTTP response parsed).
def is_transient_status(int64 status) -> bool:
    if status == 0:
        return True
    if status == 500:
        return True
    if status == 502:
        return True
    if status == 503:
        return True
    if status == 504:
        return True
    return False

# Classify a response by HTTP status + AWS error code into one of the retry
# classes above. Throttling wins over transient (HTTP 503 SlowDown is a
# throttle, not a plain transient). A 2xx never reaches here in the loop, but is
# classified `none` for completeness.
def retry_class(int64 status, str code) -> int64:
    if core.is_success(status):
        return class_none()
    if status == 429:
        return class_throttling()
    if is_throttling_code(code):
        return class_throttling()
    if is_transient_status(status):
        return class_transient()
    if is_transient_code(code):
        return class_transient()
    return class_none()

# Whether a (status, code) pair should be retried at all.
def is_retryable(int64 status, str code) -> bool:
    return retry_class(status, code) != class_none()

# ---------------------------------------------------------------------------
# Exponential backoff with full jitter
# ---------------------------------------------------------------------------

# Seed the jitter RNG so backoff is deterministic. Tests call this; live callers
# leave the RNG on its OS-entropy autoseed.
def seed_jitter(int64 s):
    random.seed(s)

# The backoff CAP for retry `attempt` (0-based: attempt 0 is the wait before the
# first retry): min(max_backoff, base_delay * 2**attempt). Deterministic (no
# RNG) — the ceiling the jittered delay is drawn under.
def backoff_cap(RetryConfig cfg, int64 attempt) -> float64:
    auto raw = cfg.base_delay * math.pow(2.0, float64(attempt))
    if raw < cfg.max_backoff:
        return raw
    return cfg.max_backoff

# The jittered backoff delay in seconds for retry `attempt` (0-based): a uniform
# draw in [0, backoff_cap]. "Full jitter" — the whole interval down to zero — is
# botocore standard mode's jitter and the best-studied choice for avoiding
# synchronized retry storms. Returns 0 when the cap is non-positive (so a
# zero-backoff config never touches the RNG, keeping such runs reproducible).
def backoff_delay(RetryConfig cfg, int64 attempt) -> float64:
    auto cap = backoff_cap(cfg, attempt)
    if cap <= 0.0:
        return 0.0
    return random.uniform(0.0, cap)

# ---------------------------------------------------------------------------
# Retry-quota token bucket (botocore `RetryQuota`)
# ---------------------------------------------------------------------------

# A per-client retry-quota token bucket. `available` is a single-element list so
# the balance is mutable in place and shared by reference: one bucket is created
# per client and threaded through every request, so a burst of failures on one
# call leaves less quota for the next — the point of the mechanism. `capacity`
# is the ceiling a refill cannot exceed.
struct RetryQuota:
    int64 capacity
    list[int64] available

# A full bucket at the given capacity (default `default_quota_capacity`).
def new_retry_quota(int64 capacity = 500) -> RetryQuota:
    return RetryQuota(capacity=capacity, available=[capacity])

# The current token balance.
def quota_balance(RetryQuota q) -> int64:
    return q.available[0]

# Try to draw `cost` tokens for a retry. Returns True and debits the bucket when
# enough tokens are available; returns False and leaves the balance untouched
# when they are not (the caller then stops retrying). botocore requires the full
# cost to be available — it does not partially debit.
def quota_acquire(RetryQuota q, int64 cost) -> bool:
    if q.available[0] < cost:
        return False
    q.available[0] = q.available[0] - cost
    return True

# Refill `amount` tokens (on a success), capped at capacity so a long-lived
# client cannot accrue unbounded retry budget.
def quota_release(RetryQuota q, int64 amount):
    auto next = q.available[0] + amount
    if next > q.capacity:
        next = q.capacity
    q.available[0] = next

# The quota cost of a retry for a given status: a connection error (status 0)
# costs more than an HTTP-level error, matching botocore's
# `TIMEOUT_RETRY_REQUEST` vs `RETRY_REQUEST`.
def retry_token_cost(RetryConfig cfg, int64 status) -> int64:
    if status == 0:
        return cfg.timeout_retry_cost
    return cfg.retry_cost

# ---------------------------------------------------------------------------
# The retry loop
# ---------------------------------------------------------------------------

# The result of a retried call: the final `Response`, the number of attempts
# actually made, the surfaced `error` (none on success), and `quota_exhausted` —
# True when the loop gave up on a still-retryable failure because the attempt cap
# was hit or the quota bucket ran dry (as opposed to surfacing a permanent
# error or a success).
struct RetryOutcome:
    core.Response response
    int64 attempts
    Optional[core.AwsError] error
    bool quota_exhausted

# Pull the AWS error code out of a response for classification ("" when none).
def response_error_code(core.Response resp) -> str:
    Optional[core.AwsError] errp = core.parse_error(resp)
    if errp.is_some():
        return errp.unwrap().code
    return ""

# Run `attempt_fn` under the standard retry policy, threading `quota`.
#
# `attempt_fn` performs one full try — in the live path it signs the request
# with a fresh timestamp and sends it (see `send_request_with_retry`); in tests
# it returns the next canned `Response`. The loop:
#   * returns on the first 2xx (refilling the bucket: the retry cost it spent on
#     this request if it retried, else the small clean-success increment);
#   * surfaces a permanent (non-retryable) error immediately;
#   * on a retryable error, stops if the attempt cap is reached or the quota
#     bucket cannot cover another retry (`quota_exhausted`), otherwise draws the
#     tokens, sleeps the jittered backoff, and tries again.
def retry_send(
    RetryConfig cfg,
    RetryQuota quota,
    fn() -> core.Response attempt_fn,
) -> RetryOutcome:
    auto attempt = 1
    auto spent = 0
    auto resp = attempt_fn()
    while True:
        if core.is_success(resp.status):
            if spent > 0:
                quota_release(quota, spent)
            else:
                quota_release(quota, cfg.no_retry_refill)
            Optional[core.AwsError] no_err = Optional.None
            return RetryOutcome(
                response=resp,
                attempts=attempt,
                error=no_err,
                quota_exhausted=False,
            )
        auto code = response_error_code(resp)
        Optional[core.AwsError] errp = core.parse_error(resp)
        if not is_retryable(resp.status, code):
            return RetryOutcome(
                response=resp,
                attempts=attempt,
                error=errp,
                quota_exhausted=False,
            )
        if attempt >= cfg.max_attempts:
            return RetryOutcome(
                response=resp,
                attempts=attempt,
                error=errp,
                quota_exhausted=True,
            )
        auto cost = retry_token_cost(cfg, resp.status)
        if not quota_acquire(quota, cost):
            return RetryOutcome(
                response=resp,
                attempts=attempt,
                error=errp,
                quota_exhausted=True,
            )
        spent = spent + cost
        auto delay = backoff_delay(cfg, attempt - 1)
        time.sleep(delay)
        attempt = attempt + 1
        resp = attempt_fn()

# Live convenience: retry a signed send of `req` to `host` with `creds`, under
# the standard policy and the given `quota`. Each attempt re-signs `req` with a
# fresh SigV4 timestamp (`sign_request_now`) — unlike the aws.core baseline,
# which re-sent identical bytes — so a retry after a clock-skew-induced failure
# carries a current timestamp. This is the method a per-service client routes
# its send path through.
def send_request_with_retry(
    RetryConfig cfg,
    RetryQuota quota,
    str host,
    core.Credentials creds,
    core.Request req,
) -> RetryOutcome:
    fn() -> core.Response attempt_fn = lambda: core.send(host, core.sign_request_now(creds, req))
    return retry_send(cfg, quota, attempt_fn)
