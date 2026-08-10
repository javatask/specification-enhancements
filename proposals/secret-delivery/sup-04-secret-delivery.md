# Secret Delivery: Reference-Based Distribution and Device-Side Sealing

**Revision 9 — 2026-08-10**

## Owner

[@javatask](https://github.com/javatask) — Andrii Melashchenko, Belden Inc.

## Summary

This SUP defines how Margo delivers secret parameter values to devices without plaintext appearing in manifests, status reports, or logs. It introduces a `Parameter.secretRef` extension for referencing secrets by name, a Margo Secrets Service (MSS) role with a single retrieval contract, mTLS authentication scoped by the device's X.509-SVID identity, and device-side obligations for sealing, injection, and residue-zero destruction.

## Reason for proposal

**Design philosophy.** Margo standardizes contracts, not products. The MSS is a role any conforming service can fill. This SUP specifies the minimum surface a voting member can evaluate in twenty minutes: what a device fetches, how it proves identity, and what it guarantees about the value once held. Mechanism lives in the non-normative companion (`sup-04-implementation-notes.md`); rationale lives in `sup-04-rationale-and-alternatives.md`.

Four gaps in the current specification motivate this proposal:

1. **No reference mechanism.** `Parameter.value` is the only supply path; there is no indirection to an external store.
2. **No retrieval contract.** No defined wire format, authentication, or error handling for fetching a referenced secret.
3. **No device-side obligation.** No requirement to seal, inject securely, or destroy secret material.
4. **No authorization contract.** No stated least-privilege rule bounding what a device may retrieve.

## Requirements alignment acknowledgement

This SUP addresses:

- **[margo/specification #145](https://github.com/margo/specification/issues/145)** — sensitive-information strategy for application management.
- **[margo/specification #129](https://github.com/margo/specification/issues/129)** — OCI credential management on devices (partial; see out-of-scope).

**Out of scope (with named successors):**

- WFM→MSS secret write path — the WFM MUST write secret values to the MSS before publishing Desired State referencing them; the write-path API is deferred to a future SUP.
- Dynamic credential issuance (short-lived tokens, just-in-time certificates) — deferred to a named successor SUP.
- OCI registry credential delivery mechanism — deferred to SUP-05 (builds on Change 5b of this SUP).
- SVID acquisition and provisioning (`specification-enhancements` PR #84, stage P1).
- MSS discovery (how a device learns the MSS network address).

**Dependency:** mTLS authentication rests on the MIAF identity model (PR #38, Approved P3; spec integration tracked by `margo/specification` PR #194, open as of this revision — re-verify before vote).

## Technical proposal

### Affected files

| File | Change type |
|---|---|
| `system-design/specification/margo-secrets-service/` (new) | MSS role + Secret Retrieval contract |
| `src/specification/applications/application-description.linkml.yaml` | Adds `Parameter.kind`, `Parameter.secretRef`, `ParameterTarget.dataKey` |
| `system-design/specification/margo-management-interface/device-capabilities.md` | Adds `secretsAtRest` field |

### Change 1: The Margo Secrets Service (MSS) role

The MSS is a **role**, not a product. It is responsible for:

- storing secret values addressed by opaque `secretRef` references;
- serving the Secret Retrieval contract (Change 3) over mTLS;
- enforcing identity-derived authorization (Change 4); and
- versioning secrets so devices detect rotation.

Any service meeting these responsibilities fills the role. The MSS MAY be operated by the WFM vendor, the end customer, or a third party; the trust consequence (the MSS holds plaintext) MUST be documented by the operator.

### Change 2: `Parameter` extension — `secretRef`

```yaml
parameters:
  - name: cloud-tenant-key
    kind: secret
    secretRef: factory-a/eh-tenant-key
    targets:
      - pointer: CLOUD_TENANT_KEY
        dataKey: apikey
        components: ["cloud-gateway"]
```

Requirements:

- `kind: secret` **MUST** carry `secretRef`, **MUST NOT** carry a literal `value`.
- A `Parameter` with no `kind` slot present **MUST** be interpreted as `kind: value` (backward-compatible default).
- A `Parameter` carrying `secretRef` without `kind: secret` **MUST** be treated as malformed; fail-closed.
- `secretRef` grammar: `^(SEG|VAR)(/(SEG|VAR))*$` where `SEG = [a-z0-9]([a-z0-9._-]*[a-z0-9])?` and `VAR = \{\{[a-z]+(\.[a-z]+)*\}\}` (see Change 7 for template variables).
- Each `/`-delimited segment **MUST** be transmitted as a literal path segment in the retrieval URL (no percent-encoding of `/`).
- `kind: secret` **MUST NOT** carry any alternative value-resolution field (e.g. `valueFrom`).
- Resolution failure (unreachable MSS, 403, 404, unknown ref) **MUST** fail the install/update operation. No fallback substitution.
- `ParameterTarget.dataKey` names the key within the response `data` object to extract. Where `data` contains exactly one key, `dataKey` MAY be omitted. Where `data` contains multiple keys, every target **MUST** carry `dataKey`; absence is a resolution failure.
- `pointer` semantics are defined per deployment profile. A `kind: secret` target **MUST NOT** reference a profile that has not yet defined `pointer` semantics.
- Secret values **MUST NOT** appear in manifests, deployment YAMLs, bundles, `margo-params.env`, status reports, or logs.

### Change 3: Secret Retrieval contract

Margo defines a single retrieval contract. The wire shape is Margo's own schema, compatible with the KV-v2 layout.

```
GET /v1/secret/data/{secretRef}
```

**Response body:**

```json
{
  "data": {
    "data": { "<key>": "<value>" },
    "metadata": { "version": 42 }
  }
}
```

Requirements:

- `data.data` (object, REQUIRED) — the secret key-value map.
- `data.metadata.version` (integer, REQUIRED, monotonic) — the change token.
- Additional fields **MAY** be present; devices **MUST** ignore unrecognized fields.
- `ETag: "<version>"` — the version integer as a quoted string, strong validator (RFC 9110 §8.8.3). **MUST NOT** use weak-validator prefix `W/`.
- `Cache-Control: no-store` — responses **MUST NOT** be cached unencrypted by any intermediary or client.
- Devices **SHOULD** use `If-None-Match` for conditional fetch; `304 Not Modified` means no change.
- Polling interval: no more than once per five minutes absent operator configuration. Devices **SHOULD** apply jitter (±20%). MSS **MAY** return `429` with `Retry-After`; devices **MUST** honor it.

**Status codes (normative):**

| Code | Meaning | Device behavior |
|---|---|---|
| 200 | Success | Process response |
| 304 | Not Modified | No action |
| 403 | Outside authorization scope | Resolution failure |
| 404 | Unknown/unresolvable secretRef | Resolution failure |
| 429 | Rate limited | Suspend polling per `Retry-After` |
| 5xx | Transient server error | Retain sealed credential, retry with backoff |

- Devices **MUST** key behavior on status code alone. Devices **MUST NOT** parse error bodies for control flow.
- MSS **SHOULD** emit RFC 9457 Problem Details bodies for diagnostic purposes.
- Any status not listed above (400, 422, etc.) during steady-state polling **MUST** be treated as transient: retain current credential, surface as fault, retry.

### Change 4: Authentication and authorization

**Authentication — sole binding:** mTLS with MIAF X.509-SVIDs.

- MSS **MUST** present a Trust-Domain-scoped X.509-SVID as its TLS server certificate.
- Device **MUST** validate the MSS's SVID against the device's Trust Domain's Trust Bundle.
- Device **MUST** verify the MSS's SPIFFE ID is exactly `spiffe://<trust-domain>/margo/mss/<mss-id>`, where `<trust-domain>` is from the device's own SVID.
- Device **MUST** treat the MSS as unauthenticated if validation fails. **MUST NOT** transmit credentials.
- Device **MUST NOT** accept an MSS whose SPIFFE ID names a different Trust Domain.
- MSS **MUST** keep its trust-anchor set current with the Trust Bundle, refreshing within `spiffe_refresh_hint` or an operator-configured interval.

**Authorization — identity-derived scope:**

- MSS **MUST NOT** serve a secretRef outside the authorization scope derived from the requesting device's verified X.509-SVID. Return 403.
- MSS **SHOULD** further narrow scope to secretRefs present in the device's current Desired State.
- WFM **MUST** write the secret value to the MSS before publishing Desired State referencing that secretRef.

**Scope withdrawal:**

- MSS **MUST** provide a means to reduce or withdraw a device's authorization scope, effective on next retrieval, independent of device-side state, Desired State publication, or device-side confirmation.

**Retrieval audit:**

- Retrieval events **MUST** be logged by the MSS, correlated to device principal, secretRef, and version.

### Change 5: Device-side obligations

| Requirement | Level |
|---|---|
| No secret plaintext on any world/group-readable path. | **MUST** |
| Devices with a hardware root of trust **MUST** seal secrets at rest, binding availability to that root. Decrypted plaintext exists only in a volatile, container-scoped location for the consuming workload's lifetime. | **MUST** |
| Devices without hardware root of trust **MUST** declare their actual posture per Change 6. A device **MUST NOT** declare a tier stronger than the protection it provides. | **MUST** |
| A container runtime's native secret-injection mechanism **MUST NOT** be claimed as at-rest protection unless documented by its maintainer to encrypt at rest. | **MUST NOT** |
| Decryption **MUST** be performed by a privileged component — never by the unprivileged consumer. | **MUST** |
| The service-manager instance consuming decrypted credentials **MUST** persist across sessions and start at boot without operator presence. | **MUST** |
| On version change (Change 3), re-seal and re-inject; restart via the component's normal update sequence. If re-sealing fails, leave workload on current credential, surface fault, retry next poll. Never persist fetched plaintext unsealed. | **MUST** |
| Transient retrieval failures during polling (5xx, timeout, DNS) **MUST NOT** tear down the workload. Continue on current sealed credential; retry with backoff. | **MUST NOT** |
| Offline restart: device **MUST** (re)start workloads from last sealed credentials without MSS connectivity. | **MUST** |
| **Residue-zero on workload removal** across: (1) durable sealed artifact; (2) volatile credential mount (unmounted, not just emptied); (3) container writable/overlay layer; (4) runtime image/content store; (5) service-manager per-session state; (6) unit/manifest definition (ciphertext or reference only); (7) system/service log sink (timestamp-bounded); (8) process environment block. Verified by a check **capable of failing**. | **MUST** |

**Sealing invalidation on update:** If sealing is bound to measured platform state and a platform update changes that state, the device **MUST** either (a) re-encrypt all sealed secrets under the post-update state before committing the transition, or (b) bind to a state predicate stable across the update class.

### Change 5b: Runtime-scoped secrets

A **runtime-scoped secret** is consumed by the device's container runtime or service manager (e.g., an OCI registry credential at image-pull time), not by a deployed workload.

| Requirement | Level |
|---|---|
| All Change 5 sealing, declaration, and destruction requirements apply without exception. | **MUST** |
| Secret **MUST** be sealed, decrypted, and placed before the runtime attempts the authorized operation. | **MUST** |
| **MAY** be injected into a device-wide or namespace-wide credential store. Destruction requirements apply to that store. | **MAY** |
| Destruction triggered by: (a) secretRef removed from all Desired State, or (b) rotation signal. Not by any single workload's removal while other referrers exist. | **MUST** |
| Rotation affects all future authorized operations device-wide. Runtime **MUST** permit operations on current value until re-sealing completes. | **MUST** |

SUP-05 (OCI registry credentials) is expected to cross-reference this Change.

### Change 6: `secretsAtRest` taxonomy

`DeviceCapabilitiesManifest` gains a `secretsAtRest` field. Permissible values:

| Value | Meaning | Resists |
|---|---|---|
| `hardware` | Bound to hardware root of trust (TPM 2.0, secure element, or equivalent). | Host-level extraction; disk imaging |
| `software` | Key not recoverable from storage medium alone (e.g., FDE with off-device unlock). | Disk imaging / theft of powered-off storage |
| `host-bound` | Encrypted to device identity, but key co-resident on same medium. | Exfiltration of sealed artifact in isolation |
| `none` | No sealing claim. | — |

Requirements:

- A device **MUST NOT** declare a tier stronger than the protection it provides.
- WFM **MUST NOT** treat a device's `secretsAtRest` declaration as attested (it is a self-report).
- WFMs **SHOULD** refuse to schedule `kind: secret` parameters onto `none` devices.
- `none` **MUST** still satisfy the "no plaintext on world/group-readable path" rule.
- Devices **MAY** additionally declare informative `sealingMechanism` and `attestationMechanism` fields.

### Change 7: secretRef template expansion

A secretRef **MAY** contain template variables for device-specific path segments.

**Grammar:**

```
SEG = [a-z0-9]([a-z0-9._-]*[a-z0-9])?
VAR = {{[a-z]+(\.[a-z]+)*}}
secretRef = ^(SEG|VAR)(/(SEG|VAR))*$
```

**Rules:**

- Variables occupy whole segments only (no intra-segment interpolation).
- Expansion is device-side exclusively.
- Variable values are derived from the device's X.509-SVID only.
- Expanded values **MUST** match `SEG`.
- Unknown variable → fail-closed (resolution failure per Change 2).
- Template expansion support is **OPTIONAL**. A device that does not support it **MUST** treat any secretRef containing `{{` as a resolution failure.

**Defined variables:**

| Variable | Source |
|---|---|
| `{{device.id}}` | Per-device segment of the device's SPIFFE ID |
| `{{device.group}}` | Group/site segment of the device's SPIFFE ID |

### Change 8: Secret injection contract

Requirements for delivering a resolved secret value to its consuming workload:

- Device **MUST** make the resolved value readable by the consuming workload and no other.
- Plaintext **MUST NOT** reach persistent storage.
- Plaintext **MUST** cease to be readable once the workload stops.
- Workload obtains the value by dereferencing a locator supplied at deployment time. `ParameterTarget.pointer` names the config key carrying the locator.
- Secret value **MUST NOT** appear in the rendered deployment document, declared configuration, or runtime-inspection/status surfaces. Only the locator **MAY** appear.

### Change 9: Encoding of non-textual secret material

Where a secret value is non-textual (binary key material, certificates in DER form, or equivalent), the MSS **MUST** encode it as base64 (RFC 4648 §4) in the `data.data` value string. A device **MUST** decode before sealing. The `data.metadata` object **MAY** carry a `contentType` field (e.g. `application/octet-stream`) to signal encoding; where absent, the device **MUST** treat the value as UTF-8 text.

### Conformance impact

| Obligation | Actor | Level |
|---|---|---|
| `kind: secret` carries `secretRef`, never literal value | WFM, Device | **MUST** |
| Resolution failure → fail install/update | Device | **MUST** |
| Single retrieval contract at `/v1/secret/data/{secretRef}` | MSS | **MUST** |
| Behavior keyed on status code, not error body | Device | **MUST** |
| mTLS with X.509-SVID, MSS SPIFFE ID validated | MSS, Device | **MUST** |
| Authorization scope derived from device identity | MSS | **MUST** |
| Scope withdrawal independent of device state | MSS | **MUST** |
| Write secret before publishing Desired State | WFM | **MUST** |
| Seal at rest (hardware devices); honest declaration (all) | Device | **MUST** |
| Privileged decryption, service persistence, offline restart | Device | **MUST** |
| Residue-zero on removal (8 surfaces) | Device | **MUST** |
| Injection by indirection; no plaintext in config/status | Device | **MUST** |
| Template expansion support | Device | **OPTIONAL** |

### Backward compatibility

This SUP is additive. `Parameter` gains optional `kind` and `secretRef`; absence of `kind` means `kind: value` (today's behavior). `DeviceCapabilitiesManifest` gains `secretsAtRest`; a device that predates this SUP simply does not declare it. No existing conformant document is invalidated.

**Breaking change for pre-ballot implementers:** Rev 9 removes the dual-profile structure (primary Margo-native envelope + KV-v2 compatibility profile) present in Rev 8. Implementations built against Rev 8's primary Margo-native envelope shape must migrate to the single KV-v2-compatible contract defined in Change 3.

### Security considerations

**Residual-risk table:**

| ID | Risk | Mitigation in this SUP | Residual |
|---|---|---|---|
| R1 | MSS compromise exposes all plaintext | Role separation; audit logging | Operator trust boundary — documented, not eliminated |
| R2 | Stolen SVID retrieves secrets until expiry | Identity-scoped authZ + scope withdrawal (Change 4) | MIAF has no OCSP/CRL; short SVID lifetime is the primary control |
| R3 | `host-bound` device: key co-resident with ciphertext | Honest declaration; WFM scheduling policy | Does not resist powered-on host compromise |
| R4 | `none` device holds secrets | WFM SHOULD refuse; `none` still requires file-permission hygiene | Operator accepts risk explicitly |
| R5 | Stale Trust Bundle admits retired anchor | MSS must refresh within `spiffe_refresh_hint` | Bounded staleness window per MIAF model |
| R6 | Platform update invalidates sealed material | Sealing-invalidation clause (Change 5) | Unplanned state change (firmware fault, tampering) not covered |
| R7 | Environment-variable injection (Compose profile) | Satisfies privilege-separation MUST | Inherited by child processes; documented exposure vector (CWE-526) |
| R8 | Restart loop on unsealable credential | Not resolved by this SUP | Device policy choice; flagged for implementers |
| R9 | Clock skew affects SVID validity | Time sync SHOULD be maintained | Operational |
| R10 | Log sink captures plaintext accidentally | Residue-zero surface (7) requires log audit | Bounded by timestamp window |
| R11 | Non-textual secret misinterpreted as text | Encoding clause (Change 9) with `contentType` signal | Absent `contentType` defaults to UTF-8 |

**Key notes:**

- The MSS holds plaintext. Operators rejecting this trust boundary should evaluate sealed-parameter alternatives (see rationale companion).
- This SUP's revocation operates at the authorization layer only — it does not revoke SVIDs.
- `software` and `host-bound` are honest declarations; neither protects a compromised running host.
- Retrieval metadata is intentionally observable and audited.

### References

- MIAF identity model — SPIFFE X.509-SVID, Trust Domain, Trust Bundle. Approved (P3) via `specification-enhancements` PR #38; integration tracked by `margo/specification` PR #194 (open — re-verify before vote).
- Margo WFM Identity Profile — Approved (P3), PR #58.
- MIAF Credential Provisioning — PR #84 (stage P1, draft, not Approved).
- RFC 9457 — Problem Details for HTTP APIs.
- RFC 9110 — HTTP Semantics (conditional requests, ETag).
- RFC 4648 — Base Encodings.
- RFC 9334 — RATS Architecture (informative).
- OpenBao (openbao.org) — reference implementation; KV v2 engine; MPL 2.0, LF/OpenSSF.
- Non-normative companions: `sup-04-rationale-and-alternatives.md`, `sup-04-implementation-notes.md`.

---

*Prepared by Andrii Melashchenko (Belden Inc.), 2026-08-10. Subject to the Open Web Foundation Contributor License Agreement.*
