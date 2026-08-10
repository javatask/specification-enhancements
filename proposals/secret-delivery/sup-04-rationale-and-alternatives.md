# SUP-04 Rationale and Alternatives

**Non-normative companion to SUP-04 Rev 9 — 2026-08-10**

This document explains the *why* behind the normative ballot text. It is intended for reviewers who want to understand design decisions, rejected alternatives, and security analysis. Nothing in this document creates a conformance obligation.

---

## Design philosophy

Margo standardizes contracts, not products. The SUP-04 ballot text is written so that:

1. **A voting member reads it in twenty minutes** and knows exactly what is being voted on.
2. **An implementer can build to it** without reading this companion — every MUST is self-contained.
3. **No product is privileged.** The MSS is a role; the retrieval contract is Margo's own schema; mechanism detail lives in the implementation-notes companion.

The guiding test: *Can two strangers, implementing independently from the ballot text alone, produce a device and an MSS that interoperate at first contact?* If yes, the normative surface is sufficient. If no, something is missing from the ballot — not from here.

---

## The Two Strangers Test

Every normative statement was evaluated against this test:

> If Stranger A builds a device and Stranger B builds an MSS, both reading only the ballot text, will Stranger A's device successfully retrieve and seal a secret from Stranger B's MSS on their first interaction?

The test requires:

- Unambiguous wire format (one shape, not two).
- Status-code-driven behavior (no body parsing for control flow).
- Identity validated from the device's own SVID (no out-of-band coordination beyond initial provisioning).
- Fail-closed defaults (a device that doesn't understand something stops, doesn't guess).

---

## The floor statement

This SUP establishes a *floor*, not a ceiling. It defines the minimum a Margo device MUST do with a secret. Operators, vendors, and deployment tools MAY layer additional protections — attestation-gated release, HSM-backed sealing, per-operation token rotation — above this floor. The ballot text deliberately avoids mandating mechanisms that would exclude resource-constrained devices or force a single vendor's stack.

---

## Direction-by-direction rationale

### D1 — Single retrieval contract (KV-v2-compatible shape)

**Rev 8 had two profiles:** a "primary" Margo-native envelope and a "KV-v2 compatibility profile." This doubled the conformance surface, confused implementers about which to target, and in practice meant that every deployment would pick one — making the other dead letter.

**Resolution:** Adopt one shape. The KV-v2 layout (`data.data` + `data.metadata.version`) was chosen because:

- It is already implemented by OpenBao unmodified (zero adaptation cost for the reference MSS).
- It carries the nested structure that naturally accommodates multi-key secrets.
- Margo defines this as *its own schema* — it happens to be wire-compatible with KV-v2, but the normative authority is the Margo spec, not any third-party API documentation.

The "primary Margo-native" shape from Rev 8 (flat `secretRef`, `version`, `data`) had cleaner aesthetics but no implementation backing and would have required every KV-v2 backend to add an adapter layer.

### D2 — Status codes normative, error body not

Error bodies vary wildly between implementations. Requiring RFC 9457 as a control surface would force implementers into body-parsing logic that is fragile and vendor-specific. The device's contract is simple: react to the status code. The MSS SHOULD emit RFC 9457 for human diagnostics; it's good practice, not a conformance gate for the device.

### D3 — Authorization by identity-derived scope

**Rev 8's policy-sync sub-contract** was the longest section in the document (~120 lines): path grammar, entity mapping, grant ordering, revocation ordering, batch-splitting, confirmation semantics, an interoperability limitation note. It was also the section most likely to block adoption — it mandated a WFM→MSS synchronization protocol that no two independent implementations could interoperate on without custom glue.

**Resolution:** Replace with a simple invariant: the MSS derives authorization scope from the device's verified identity. How the MSS internally maps identity to allowed paths is an implementation detail, not a Margo contract. The normative requirements are:

- MUST NOT serve outside scope (403).
- SHOULD narrow to current Desired State.
- MUST provide scope withdrawal independent of device state.

This preserves the security property (least privilege) without prescribing the mechanism (policy sync, RBAC, OPA, whatever).

### D3b — Scope withdrawal

A device's authorization scope MUST be reducible without the device's cooperation. This is the only immediate control available when a device is compromised — MIAF has no OCSP/CRL for SVIDs. Without this requirement, revoking access would require waiting for SVID expiry or rotating the entire Trust Domain's anchor.

### D4 — secretRef template expansion

Templates solve the fleet-credential problem: one ApplicationDescription, N devices, each needing a device-specific secret path. Without templates, the WFM must generate N distinct ApplicationDeployment documents differing only in the secretRef path segment — an O(N) manifest-management burden.

**Design choices:**

- Whole-segment only: avoids regex complexity and injection risks.
- Device-side expansion: the WFM doesn't need to know device-specific path segments.
- SVID-derived values only: no new identity surface; uses what the device already has.
- OPTIONAL support: devices that don't need it aren't burdened with a template parser.

### D5 — WFM→MSS write path out of scope

The write path is a WFM-internal concern with wildly different implementations (API call, GitOps, manual upload). Specifying it would privilege one pattern. The one invariant that matters is timing: the secret MUST exist before the manifest references it. Everything else is operator tooling.

### D6 — Dynamic credential issuance out of scope

Short-lived tokens and just-in-time certificates are a fundamentally different pattern (push vs. pull, no sealing needed, different rotation model). Conflating them with static secrets would bloat the ballot and confuse the conformance surface. Named as a successor so the working group knows it's tracked.

### D7 — RFC 9421 compatibility profile retired

**Rev 8 retained RFC 9421** as a sunset transition path for deployments without MIAF SVIDs. User direction overrides the PR #194 gate. Rationale for removal:

- RFC 9421 establishes a different principal type (Client-ID + certificate) than what the authorization contract is written against (SPIFFE ID). Retaining it meant maintaining a permanent carve-out: "this profile MUST NOT claim conformance to least-privilege authorization."
- The "two weak postures" security consideration (a device on RFC 9421 + `host-bound` has no assurance on either axis) was an honest admission that the profile couldn't deliver the SUP's core property.
- PR #194 is the blocker, but PR #194 is about spec-text integration — MIAF itself is Approved (P3). Devices implementing this SUP are building to MIAF regardless.
- Removing it simplifies the ballot from ~400 lines to ~200. A twenty-minute read becomes achievable.

**Impact on existing implementers:** Any implementation built against Rev 8's RFC 9421 profile must migrate to mTLS. This is a pre-ballot breaking change — acceptable because no upstream PR exists yet.

### D8 — Secret injection contract

Rev 8's Change 5 implied injection but never stated it as a standalone contract. The injection requirements (readable only by consumer, no persistence, ceases on stop, value never in config/status surfaces) were scattered across the residue-zero and privilege-separation rules. Making them explicit as Change 8 gives implementers a clear checklist and reviewers a clear conformance target.

**Indirection principle:** The workload never "knows" where the secret came from — it dereferences a locator (a file path, an env var name). This means:

- The deployment doc contains only the locator, not the value.
- Status/inspection surfaces show only the locator.
- The device can rotate the underlying value without changing the workload's configuration.

---

## Worked production case: Belden BRP + sensor gateway

A Belden Building & Remote Power (BRP) gateway runs two workloads:

1. **Cloud connector** — pushes telemetry to a cloud MQTT broker. Needs a tenant API key (`cloud-tenant-key`).
2. **Sensor bridge** — talks to local Modbus/BACnet devices. Needs a local authentication credential (`sensor-auth`).

Under this SUP:

```yaml
parameters:
  - name: cloud-tenant-key
    kind: secret
    secretRef: site-{{device.group}}/cloud-tenant-key
    targets:
      - pointer: MQTT_API_KEY
        components: ["cloud-connector"]
  - name: sensor-auth
    kind: secret
    secretRef: devices/{{device.id}}/sensor-auth
    targets:
      - pointer: /run/secrets/sensor-auth
        components: ["sensor-bridge"]
```

**Flow:**

1. WFM writes both secrets to MSS before publishing Desired State.
2. Device expands `{{device.group}}` → `building-7`, `{{device.id}}` → `brp-gateway-042`.
3. Device presents X.509-SVID via mTLS; MSS validates identity, checks scope, serves secrets.
4. Device seals both values (TPM-bound on this hardware → `secretsAtRest: hardware`).
5. At workload start: privileged component decrypts, injects into volatile mounts.
6. On power loss + restart: workloads start from sealed credentials without MSS connectivity.
7. On cloud-tenant-key rotation: device detects version bump, re-seals, re-injects, restarts cloud-connector.
8. On workload removal: residue-zero across all 8 surfaces.

---

## Alternatives considered

| Alternative | Verdict | Reasoning |
|---|---|---|
| HashiCorp Vault as reference impl | Rejected | BUSL 1.1 incompatible with LF open-standard embedding. OpenBao is the same lineage under MPL 2.0/LF governance. |
| SPIRE Server + custom Go REST broker | Viable | Rebuilds KV storage/versioning/policy that OpenBao ships. Natural path if a future MIAF SUP mandates SPIRE. |
| flightctl `platform/secret` provider | Design reference | Architecturally aligned (SecretRef → systemd credentials, Apache 2.0); coupled to flightctl fleet model rather than Margo Management Interface. |
| Keylime attestation-gated delivery | Optional enhancement | Requires live verifier connectivity, conflicting with offline-restart MUST. Noted under `attestationMechanism`. |
| Kubernetes ESO / CSI Secrets Store | Rejected standalone | Control-plane-tethered. ESO retained as design reference for the reference/fetch/inject split pattern. |
| Sealed Secrets (Bitnami) | Rejected | Embeds ciphertext in manifests — violates reference-only rule. Decryption requires in-cluster controller. |
| Mechanism-keyed `secretsAtRest` enum | Rejected | A `tpm2 | software | none` enum has no honest slot for a non-TPM secure element or a legacy device with neither. Threat-keyed tiers let every device declare something true. |
| Dual retrieval profiles (Rev 8) | Superseded | Doubled conformance surface for no interoperability gain. In practice every deployment picks one. |
| Drop RFC 9421 entirely (Rev 8 alternative) | Adopted in Rev 9 | Cleaner, simpler, single principal type. Acceptable as pre-ballot breaking change. |
| KV-v2 as sole AND primary target | Adopted in Rev 9 | One shape, proven implementable, zero-adaptation for reference MSS. |
| Compose `secretRef` onto `valueFrom` (PR #54) | Rejected | PR #54's fallback-on-failure semantics are incompatible with fail-closed. Composing would import plaintext-fallback hazard. |
| SOPS + age sealed parameters | Complement, not baseline | File-format-based; no pull API, no rotation daemon. Suits air-gapped/WFM-untrusted deployments. Remains a valid alternative conformance path for those cases. |
| Co-equal dual binding (mTLS or RFC 9421) | Rejected | Authorization binds to SPIFFE ID; RFC 9421 establishes a different principal. "Either" would mean "least privilege on one path, undefined on the other." |

---

## Security analysis

### Trust boundaries

```
┌─────────┐         mTLS          ┌─────────┐
│  Device  │◄─────────────────────►│   MSS   │ ← holds plaintext
│ (SVID)   │                       │ (SVID)  │
└─────────┘                       └─────────┘
     │                                  ▲
     │ sealed credential                │ write path (out of scope)
     ▼                                  │
┌─────────┐                       ┌─────────┐
│ Workload │ ← plaintext only     │   WFM   │
│          │   in volatile mount  │         │
└─────────┘                       └─────────┘
```

**Key trust decisions:**

- The MSS sees plaintext. This is the fundamental trust boundary. Operators who reject it should use sealed-parameter alternatives (SOPS + age).
- The device seals; the workload only sees plaintext in volatile injection.
- The WFM writes secrets but need not hold them long-term (write path is out of scope; timing is in scope).

### Why authorization-layer revocation matters

MIAF has no OCSP/CRL. A compromised SVID remains valid until expiry or anchor rotation (both slow, fleet-wide). During that window, the only mechanism that can immediately stop a specific device from retrieving secrets is this SUP's scope-withdrawal requirement (Change 4). This is why D3b exists as a MUST, not a SHOULD.

### The `host-bound` tier divergence from industry frameworks

Every established assurance scheme (PSA Certified, FIPS 140-3, Common Criteria, TCG, IEC 62443-4-2, ETSI EN 303 645, IETF RATS/EAT) classifies a co-resident-key configuration at its lowest tier. This SUP's `host-bound` deliberately diverges.

**Why:** Those schemes lump "no sealing at all" and "sealed to device identity, key co-resident" together. Both fail against a compromised running host. But they do NOT fail identically against an attacker who obtains only the sealed artifact in isolation (a leaked backup, a mis-committed unit file). `host-bound`'s device-key binding is a real barrier there; `none` offers nothing.

Collapsing that distinction forces devices into a false binary: over-claim `software` or be treated identically to `none`. The WG should expect this question from reviewers familiar with PSA/FIPS/EAT. The answer: those tiers grade isolation of the attesting environment; this tier grades at-rest exfiltration resistance. Different axis, different granularity.

### EAT (RFC 9711) relationship

EAT's `security-level` (1–4) grades the isolation of the *Attesting Environment that signs the claim*. This SUP's `secretsAtRest` grades *at-rest exfiltration resistance of stored secrets*. A naive 1:1 mapping would misrepresent both — `host-bound` maps to EAT level 1 (unrestricted), which is the same as `none`. That's exactly the collapse we're avoiding. Implementers MUST NOT construct or imply such a mapping.

Where a device produces EAT evidence, it is a separate, independently-interpreted signal alongside `secretsAtRest`. The two are complementary, not substitutes.

### Self-declaration limitation

`secretsAtRest` is a self-report. No appraisal mechanism exists in this revision. A future SUP building CoRIM/EAT-based appraisal on top of this taxonomy is a natural extension. Until then, the WFM treats the declaration as trusted-but-unverified — identical to every other DeviceCapabilities field today.

### Environment-variable injection (Compose profile)

Where `pointer` targets an environment variable (Compose profile), the injection satisfies privilege-separation (decryption happens in the privileged component creating the container) and the world/group-readable prohibition (`/proc/<pid>/environ` is owner-readable). But env vars are inherited by child processes and are documented exposure vectors (CWE-526) via crash dumps and debug tools.

This is an honest, bounded exposure — comparable to `host-bound`'s honesty about co-resident keys. Operators with tighter requirements SHOULD use the Compose Specification's native `secrets:` element (file-mounted under `/run/secrets/`) instead.

### Restart posture tension

A failed-and-stopped service is diagnosable. A restart-looping service serves the offline-restart guarantee but obscures the root cause. This SUP does not resolve this tension — it's a device-policy choice. Flagged because implementers must choose, and the choice affects operational visibility.

---

## Forward-compatible notes

- **PR #77 (read receipts):** If adopted, provides device-confirmed adoption of Desired State revisions. Useful for audit correlation but not a prerequisite for any normative requirement in this SUP.
- **DeviceCapabilities bisection proposal:** If the static/dynamic split lands, `secretsAtRest` migrates to a capability-scoped ProfileDefinition. Semantics unchanged.
- **PR #54 (valueFrom):** If adopted, coexists with `kind: secret` at the schema level. The MUST NOT rules in Change 2 foreclose ambiguity.
- **Quadlet profile (PR #69):** Once it defines `pointer` semantics, the deployment-profile prerequisite in Change 2 lifts automatically.
- **SUP-05:** Builds on Change 5b for OCI registry credential delivery.

---

## Reference implementation statement

| Layer | Reference | License | Notes |
|---|---|---|---|
| MSS server | OpenBao Server | MPL 2.0, LF/OpenSSF | KV v2 engine + TLS cert auth. Wire-compatible with the single retrieval contract. |
| Device fetch | OpenBao Agent | MPL 2.0 | Auto-auth, local proxy. Agent cache is NOT the durable artifact — sealed file is. |
| Device sealing | OS-native mechanism per declared tier | — | See `sup-04-implementation-notes.md` |
| Device injection | Volatile mount or env var per deployment profile | — | See implementation notes |
| Optional attestation | e.g. rust-keylime (Apache 2.0, CNCF Sandbox) | — | Secrets released only after attestation passes |

**Rejected as normative basis:**

- HashiCorp Vault — BUSL 1.1
- Sealed Secrets — ciphertext in manifests
- ESO/CSI Secrets Store — Kubernetes-tethered
- hawkBit DDI — no KV/TPM mapping
- AGPL managers (Infisical CE, Bitwarden Unified) — copyleft risk
- flightctl — coupled to fleet model (design reference, not drop-in)

**Licensing note:** MPL 2.0 is file-level weak copyleft; embedding unmodified OpenBao Agent requires no source disclosure of integrator's own code. Formal clearance follows standard open-source review (route to IP Counsel before product commitment).

---

*This document is non-normative. The ballot text is `sup-04-secret-delivery.md`.*
