# ADR 0009: Constrain cloud-worker input retrieval

- Status: accepted
- Date: 2026-08-24

## Context

A future worker will receive short-lived object URLs. Both the URL and returned
bytes cross a trust boundary. Allowing arbitrary destinations or unbounded
decode behavior would expose the worker to SSRF, metadata-service access,
resource exhaustion, and evidence substitution.

## Decision

The HTTP fetcher accepts HTTPS URLs only and exact configured hostnames. It
resolves each destination before connecting and rejects non-global, loopback,
private, link-local, multicast, reserved, unspecified, and metadata-service
addresses. Environment proxy settings are ignored. Redirects are disabled by
default; when explicitly enabled, every target repeats scheme, host, and IP
validation within a small configured hop limit.

Responses must be identity encoded and match the approved MIME type. Streaming
is bounded by the configured maximum and approved job length. SHA-256 and byte
count are computed during the write and must match the shared `DetectorJob`
before decode or inference. Partial files are removed on every handled failure.
External errors contain neither URLs nor query strings.

The decoder independently verifies the image signature and permits JPEG, PNG,
or WebP only. It converts Pillow decompression-bomb warnings to errors, rejects
truncation, bounds width, height, pixels, and decoded-memory estimate, applies
EXIF orientation, and produces RGB with no retained metadata.

## Consequences

Object-store hostnames must be explicitly configured. A custom connection
backend repeats DNS policy at connect time and opens TLS to the validated
literal address while retaining the approved hostname for certificate checks,
closing the normal DNS-rebinding window. Cloud egress filtering remains an
independent defense-in-depth requirement. Signed URL values are never logged or
returned.
