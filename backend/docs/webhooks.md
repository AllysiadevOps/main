# Webhook delivery and signature verification

Harpocrates sends an HTTP `POST` to each active subscription when a proof
event is queued for delivery. Deliveries are **at-least-once**: a subscriber
may receive the same event more than once, so handlers must be idempotent.

The implementation lives in [`webhook.py`](../webhook.py). This document
describes the wire format that integrators must validate; it does not define a
subscription-management API.

## Request headers

| Header | Value | Notes |
| --- | --- | --- |
| `Content-Type` | `application/json` | Body is UTF-8 JSON. |
| `X-Harpocrates-Signature` | `t=<unix-seconds>,v1=<hex>` | Signature and timestamp. No spaces. |
| `User-Agent` | `Harpocrates-Webhook/1.0` | Identifies the sender. |

There is no separate delivery-ID or event-ID header. The payload itself is the
source of event identity.

## Payload fields

The dispatcher selects the event row from `proof_events` and sends these fields.
Every field is present on every request; fields without a value are JSON
`null`.

| Field | Type | Meaning |
| --- | --- | --- |
| `event_type` | string | Stored proof-event type. Current writers use `embed`, `extract`, and `register`; unknown values should be accepted for forward compatibility. |
| `file_name` | string \| null | Normalized original filename, when recorded. |
| `video_hash` | string \| null | 64-character lowercase hex video/evidence hash. |
| `metadata_hash` | string \| null | 64-character lowercase hex canonical metadata hash. |
| `proof_id` | string \| null | 64-character lowercase hex proof identifier. |
| `tier` | string \| null | Proof tier such as `silent`, `source`, or `seal`. |
| `embedded_hash` | string \| null | 64-character lowercase hex hash of the embedded artifact, when applicable. |
| `tx_hash` | string \| null | Stellar transaction hash, when a registration supplied one. |
| `tx_status` | string \| null | Registration reconciliation state, for example `pending`, `confirmed`, `failed`, or `missing`. |
| `source_address` | string \| null | Stellar source account associated with the registration. |
| `contract_id` | string \| null | Soroban contract identifier associated with the registration. |
| `metadata` | object \| null | Redacted metadata stored with the event. Never contains private witness material. |
| `created_at` | string \| null | Event creation time as an ISO 8601 timestamp, normally with a UTC offset. |

Example payload (formatted for readability; the actual body is compact JSON):

```json
{
  "event_type": "embed",
  "file_name": "evidence.mp4",
  "video_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "metadata_hash": null,
  "proof_id": null,
  "tier": null,
  "embedded_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "tx_hash": null,
  "tx_status": null,
  "source_address": null,
  "contract_id": null,
  "metadata": null,
  "created_at": "2026-10-19T12:00:00+00:00"
}
```

The body that is signed and sent is produced with Python's
`json.dumps(payload, separators=(",", ":")).encode("utf-8")`. That means no
spaces after `:` or `,`, and non-ASCII characters are escaped by default.

## Signature algorithm

The signature is an HMAC-SHA-256 over the exact request body, keyed by the
subscription's `secret_key`. The signed message is:

```text
UTF-8(decimal_unix_timestamp) || b"." || raw_request_body_bytes
```

where `raw_request_body_bytes` is the bytes received in the HTTP body, not a
re-serialization of the parsed JSON. Specifically, `sign_payload` computes:

```python
mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
mac.update(f"{timestamp}.".encode("utf-8"))
mac.update(payload_bytes)
signature = mac.hexdigest()
```

- `timestamp` is an integer number of Unix seconds, the same value sent in
  `t=`.
- The separator is a single ASCII period (`.`). There is no newline, space, or
  other prefix.
- The digest is lowercase hexadecimal.
- The header is `X-Harpocrates-Signature: t=<timestamp>,v1=<signature>`.

Because the body bytes are signed verbatim, verify against the raw request
body before parsing it. Re-encoding parsed JSON can change key order, escaping,
whitespace, or number formatting and will invalidate an otherwise valid
signature.

### Replay tolerance

The timestamp is inside the signed message, so an attacker cannot change it
without invalidating the signature. Still, a captured request is valid forever
unless the receiver enforces freshness. Reject requests whose timestamp is too
far from the receiver's clock; a common tolerance is **five minutes (300
seconds)**. Keep the tolerance small enough to bound replay exposure and large
enough to tolerate clock skew.

For duplicate at-least-once deliveries, also make processing idempotent. A
useful de-duplication key is derived from stable payload fields such as
`event_type`, `proof_id`, `tx_hash`, and `created_at`. Do not use the signature
as an idempotency key: each retry is re-signed with a new timestamp.

## Verification examples

Both examples verify the raw body bytes and use a constant-time comparison.
They fail closed on malformed headers, missing fields, stale timestamps, or a
signature mismatch.

### Python

```python
import hashlib
import hmac
import time


def verify_webhook(body: bytes, signature_header: str, secret: str,
                   tolerance_seconds: int = 300) -> bool:
    parts = {}
    for item in signature_header.split(","):
        key, separator, value = item.strip().partition("=")
        if not separator:
            return False
        parts[key] = value

    try:
        timestamp = int(parts["t"])
        received = parts["v1"]
    except (KeyError, ValueError):
        return False

    if abs(int(time.time()) - timestamp) > tolerance_seconds:
        return False

    signed = f"{timestamp}.".encode("utf-8") + body
    expected = hmac.new(
        secret.encode("utf-8"), signed, hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, received)


# Flask example: body = request.get_data()
```

### Node.js

```javascript
const crypto = require("crypto");

function verifyWebhook(body, signatureHeader, secret, toleranceSeconds = 300) {
  const parts = {};
  for (const item of signatureHeader.split(",")) {
    const separator = item.indexOf("=");
    if (separator === -1) return false;
    parts[item.slice(0, separator).trim()] = item.slice(separator + 1).trim();
  }

  const timestamp = Number(parts.t);
  if (!Number.isInteger(timestamp) || !parts.v1) return false;

  if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > toleranceSeconds) {
    return false;
  }

  const signed = Buffer.concat([
    Buffer.from(`${timestamp}.`, "utf8"),
    body,
  ]);
  const expected = crypto.createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(signed)
    .digest("hex");
  const received = Buffer.from(parts.v1, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");

  return received.length === expectedBuffer.length &&
    crypto.timingSafeEqual(received, expectedBuffer);
}

// Express example: use express.raw({ type: "application/json" }) so `body`
// is the untouched Buffer instead of parsed JSON.
```

## Test vector

The following compact body is used by the backend test suite to keep this
document and `sign_payload` in sync:

```text
body:      {"event_type":"embed","video_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
secret:    whsec_test_secret
timestamp: 1700000000
header:    t=1700000000,v1=279de12b5d5c5157d75c884b6cad8caef222af865638c922969ed4e920c5beaf
```

## Delivery, retries, and backoff

Only a `2xx` response counts as success. Any non-`2xx` status, connection error,
timeout, or oversized response is a failed attempt. The dispatcher's default
timeouts are 5 seconds to connect and 10 seconds per read, and it reads at most
64 KiB of the response body. Return a response promptly and keep the body
small.

Deliveries are leased before dispatch so multiple workers do not send the same
row concurrently:

- up to 10 ready deliveries are leased at a time;
- a lease lasts 30 seconds;
- the worker polls every 2 seconds;
- if a worker dies before updating a delivery, the lease expires and the
  delivery becomes eligible again.

The backend allows **five retries after the initial attempt**, for six HTTP
attempts total. There is no jitter. Each failure below uses the delay that
follows it:

| Attempt | `retry_count` during attempt | If the attempt fails |
| --- | --- | --- |
| Initial | 0 | `failed`; next attempt after 10 seconds |
| Retry 1 | 1 | next attempt after 60 seconds |
| Retry 2 | 2 | next attempt after 300 seconds (5 minutes) |
| Retry 3 | 3 | next attempt after 3,600 seconds (1 hour) |
| Retry 4 | 4 | next attempt after 86,400 seconds (24 hours) |
| Retry 5 | 5 | `dead_letter`; no further attempts |

A successful attempt is marked `success` and stops retrying. A delivery that
exhausts the schedule is marked `dead_letter` and is not selected again. The
last HTTP response code is recorded when one was received; transport failures
may leave it empty. Every retry reuses the same payload but gets a new
timestamp and signature.
