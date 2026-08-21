# SUP-04 Rationale, Alternatives, and Implementation Notes

> **Non-normative companion to SUP-04 (Secret Delivery).** This document explains design decisions, rejected alternatives, security analysis, and implementation guidance. Nothing here creates a conformance obligation. Where this document describes a mechanism, conformance is judged against the MUSTs in `sup-04-secret-delivery.md`, not against the mechanism described here.

---

## 1. Design philosophy

### The Two Strangers Test

Every normative statement was evaluated against this test:

> If Stranger A builds a device and Stranger B builds an MSS, both reading only the ballot text, will Stranger A's device successfully retrieve and seal a secret from Stranger B's MSS on their first interaction?

The test requires:

- Unambiguous wire format (one shape, not two).
- Status-code-driven behavior (no body parsing for control flow).
- Identity validated from the device's own SVID (no out-of-band coordination beyond initial provisioning).
- Fail-closed defaults (a device that doesn't understand something stops, doesn't guess).

### The floor statement

This SUP establishes a *floor*, not a ceiling. It defines the minimum a Margo device MUST do with a secret. Operators, vendors, and deployment tools MAY layer additional protections — attestation-gated release, HSM-backed sealing, per-operation token rotation — above this floor. The ballot text avoids mandating mechanisms that would exclude resource-constrained devices or force a single vendor's stack.

---

## 2. Decision rationale

### Why a single retrieval contract (KV-v2-compatible shape)

A dual-profile approach (separate "Margo-native" envelope + "KV-v2 compatibility profile") doubles the conformance surface, confuses implementers about which to target, and in practice means every deployment picks one — making the other dead letter.

The KV-v2 layout (`data.data` + `data.metadata.version`) was chosen because:

- Already implemented by OpenBao unmodified (zero adaptation cost for the reference MSS).
- Carries nested structure that naturally accommodates multi-key secrets.
- Margo defines this as *its own schema* — it happens to be wire-compatible with KV-v2, but the normative authority is the Margo spec.

A flat envelope shape (`secretRef`, `version`, `data`) had cleaner aesthetics but no implementation backing and would require every KV-v2 backend to add an adapter layer.

### Why no policy-sync sub-contract

A WFM→MSS policy synchronization protocol (~120 lines in early drafts: path grammar, entity mapping, grant ordering, revocation ordering, batch-splitting, confirmation semantics) was the section most likely to block adoption. It mandated a synchronization protocol that no two independent implementations could interoperate on without custom glue.

Replacement: the MSS derives authorization scope from the device's verified identity. How the MSS internally maps identity to allowed paths is an implementation detail, not a Margo contract. The normative requirements are:

- MUST NOT serve outside scope (403).
- SHOULD narrow to current Desired State.
- MUST provide scope withdrawal independent of device state.

This preserves least privilege without prescribing mechanism (policy sync, RBAC, OPA, whatever).

### Why scope withdrawal is a MUST

MIAF has no OCSP/CRL for SVIDs. A compromised SVID remains valid until expiry or anchor rotation (both slow, fleet-wide). During that window, the only mechanism that can immediately stop a specific device from retrieving secrets is scope withdrawal. Without it, revoking access requires waiting for SVID expiry or rotating the entire Trust Domain's anchor.

### Why no RFC 9421

RFC 9421 establishes a different principal type (Client-ID + certificate) than what the authorization contract is written against (SPIFFE ID). Retaining it would mean maintaining a permanent carve-out: "this profile MUST NOT claim conformance to least-privilege authorization."

Additional reasons:

- A device on RFC 9421 + `host-bound` has no assurance on either axis — "two weak postures."
- PR #194 (spec integration of MIAF) is the blocker, but MIAF itself is Approved (P3). Devices implementing this SUP build to MIAF regardless.
- Removing it cuts the ballot from ~400 lines to ~200. A twenty-minute read becomes achievable.

**Impact:** Any implementation built against an RFC 9421 profile must migrate to mTLS. Acceptable as a pre-ballot breaking change.

### Why template expansion

Templates solve the fleet-credential problem: one ApplicationDescription, N devices, each needing a device-specific secret path. Without templates, the WFM must generate N distinct ApplicationDeployment documents differing only in the secretRef path segment — an O(N) manifest-management burden.

Design choices:

- Whole-segment only: avoids regex complexity and injection risks.
- Device-side expansion: the WFM doesn't need to know device-specific path segments.
- SVID-derived values only: no new identity surface.
- OPTIONAL support: devices that don't need it aren't burdened with a template parser.

### Why injection by indirection

The workload never "knows" where the secret came from — it dereferences a locator (a file path, an env var name). This means:

- The deployment doc contains only the locator, not the value.
- Status/inspection surfaces show only the locator.
- The device can rotate the underlying value without changing the workload's configuration.

Making injection explicit as Change 8 gives implementers a clear checklist and reviewers a clear conformance target.

### Why the WFM→MSS write path is out of scope

The write path is a WFM-internal concern with wildly different implementations (API call, GitOps, manual upload). Specifying it would privilege one pattern. The one invariant that matters — the secret MUST exist before the manifest references it — is normative. Everything else is operator tooling.

---

## 3. Worked example: Belden BRP + sensor gateway

A Belden Building & Remote Power (BRP) gateway runs two workloads:

1. **Cloud connector** — pushes telemetry to a cloud MQTT broker. Needs a tenant API key (`cloud-tenant-key`).
2. **Sensor bridge** — talks to local Modbus/BACnet devices. Needs a local authentication credential (`sensor-auth`).

**Desired State fragment:**

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
7. On cloud-tenant-key rotation: device detects version bump via ETag, re-seals, re-injects, restarts cloud-connector.
8. On workload removal: residue-zero across all 8 surfaces.

---

## 4. Alternatives considered

| Alternative | Verdict | Reasoning |
|---|---|---|
| HashiCorp Vault as reference impl | Rejected | BUSL 1.1 incompatible with LF open-standard embedding. OpenBao is the same lineage under MPL 2.0/LF governance. |
| SPIRE Server + custom Go REST broker | Viable | Rebuilds KV storage/versioning/policy that OpenBao ships. Natural path if a future MIAF SUP mandates SPIRE. |
| flightctl `platform/secret` provider | Design reference | Architecturally aligned (SecretRef → systemd credentials, Apache 2.0); coupled to flightctl fleet model rather than Margo Management Interface. |
| Keylime attestation-gated delivery | Optional enhancement | Requires live verifier connectivity, conflicting with offline-restart MUST. Noted under `attestationMechanism`. |
| Kubernetes ESO / CSI Secrets Store | Rejected standalone | Control-plane-tethered. ESO retained as design reference for the reference/fetch/inject split pattern. |
| Sealed Secrets (Bitnami) | Rejected | Embeds ciphertext in manifests — violates reference-only rule. Decryption requires in-cluster controller. |
| Mechanism-keyed `secretsAtRest` enum | Rejected | A `tpm2 | software | none` enum has no honest slot for a non-TPM secure element or a legacy device with neither. Threat-keyed tiers let every device declare something true. |
| Dual retrieval profiles | Superseded | Doubled conformance surface for no interoperability gain. In practice every deployment picks one. |
| Co-equal dual auth binding (mTLS or RFC 9421) | Rejected | Authorization binds to SPIFFE ID; RFC 9421 establishes a different principal. "Either" would mean "least privilege on one path, undefined on the other." |
| Compose `secretRef` onto `valueFrom` (PR #54) | Rejected | PR #54's fallback-on-failure semantics are incompatible with fail-closed. Composing would import plaintext-fallback hazard. |
| SOPS + age sealed parameters | Complement, not baseline | File-format-based; no pull API, no rotation daemon. Suits air-gapped/WFM-untrusted deployments. Valid alternative conformance path for those cases. |

---

## 5. Security analysis

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

### Key trust decisions

- The MSS sees plaintext. This is the fundamental trust boundary. Operators who reject it should use sealed-parameter alternatives (SOPS + age).
- The device seals; the workload only sees plaintext in volatile injection.
- The WFM writes secrets but need not hold them long-term (write path is out of scope; timing is in scope).

### Authorization-layer revocation

MIAF has no OCSP/CRL. A compromised SVID remains valid until expiry or anchor rotation (both slow, fleet-wide). During that window, the only mechanism that can immediately stop a specific device from retrieving secrets is this SUP's scope-withdrawal requirement. This is why scope withdrawal is a MUST, not a SHOULD.

### The `host-bound` tier divergence from industry frameworks

Every established assurance scheme (PSA Certified, FIPS 140-3, Common Criteria, TCG, IEC 62443-4-2, ETSI EN 303 645, IETF RATS/EAT) classifies a co-resident-key configuration at its lowest tier. This SUP's `host-bound` deliberately diverges.

**Why:** Those schemes lump "no sealing at all" and "sealed to device identity, key co-resident" together. Both fail against a compromised running host. But they do NOT fail identically against an attacker who obtains only the sealed artifact in isolation (a leaked backup, a mis-committed unit file). `host-bound`'s device-key binding is a real barrier there; `none` offers nothing.

Collapsing that distinction forces devices into a false binary: over-claim `software` or be treated identically to `none`. The WG should expect this question from reviewers familiar with PSA/FIPS/EAT. The answer: those tiers grade isolation of the attesting environment; this tier grades at-rest exfiltration resistance. Different axis, different granularity.

### Self-declaration limitation

`secretsAtRest` is a self-report. No appraisal mechanism exists in this revision. A future SUP building CoRIM/EAT-based appraisal on top of this taxonomy is a natural extension. Until then, the WFM treats the declaration as trusted-but-unverified — identical to every other DeviceCapabilities field today.

### EAT (RFC 9711) relationship

EAT's `security-level` (1–4) grades the isolation of the *Attesting Environment that signs the claim*. This SUP's `secretsAtRest` grades *at-rest exfiltration resistance of stored secrets*. A naive 1:1 mapping would misrepresent both — `host-bound` maps to EAT level 1 (unrestricted), which is the same as `none`. That's exactly the collapse we avoid. Implementers should not construct or imply such a mapping — the axes are incommensurable.

Where a device produces EAT evidence, it is a separate, independently-interpreted signal alongside `secretsAtRest`. The two are complementary, not substitutes.

### Environment-variable injection (Compose profile)

Where `pointer` targets an environment variable (Compose profile), the injection satisfies privilege-separation (decryption happens in the privileged component creating the container) and the world/group-readable prohibition (`/proc/<pid>/environ` is owner-readable). But env vars are inherited by child processes and are documented exposure vectors (CWE-526) via crash dumps and debug tools.

This is an honest, bounded exposure — comparable to `host-bound`'s honesty about co-resident keys. Operators with tighter requirements SHOULD use the Compose Specification's native `secrets:` element (file-mounted under `/run/secrets/`) instead.

### Restart posture tension

A failed-and-stopped service is diagnosable. A restart-looping service serves the offline-restart guarantee but obscures the root cause. This SUP does not resolve this tension — it's a device-policy choice. Flagged because implementers must choose, and the choice affects operational visibility.

---

## 6. Implementation notes

> The OS- and product-version facts in this section are perishable. The SUP states outcomes; this section states one way to achieve them today. Every fact carries its verification date and source. **Re-verify before relying operationally.**

### 6.1 Device sealing — `systemd-creds`

**Reference mechanism:** `systemd-creds` — the tool, and the `LoadCredentialEncrypted=` / `SetCredentialEncrypted=` service-file directives.

| Claim | Source | Verified |
|---|---|---|
| System-scope credential sealing available from systemd **v250**. | `systemd/systemd` NEWS, "CHANGES WITH 250" | 2026-08-07 |
| Rootless / `--user`-scope decryption requires systemd **v258**. Before v258, a `--user`-scope service manager cannot decrypt an encrypted credential at all. | `systemd/systemd` NEWS, "CHANGES WITH 258": *"Encrypted systemd service credentials are now available for user services too, including if locked to TPM."* | 2026-08-07 |
| Rootless decryption path (v258+): `systemd-creds.socket` Varlink service, system-manager-owned (`/run/systemd/io.systemd.Credentials`), socket-activates root-privileged `systemd-creds@.service`. The rootless unit's own unprivileged process never performs decryption. | `systemd/systemd` `units/systemd-creds.socket` + `units/systemd-creds@.service` @ tag `v258` | 2026-08-07 |
| Decrypted plaintext lands in tmpfs `/run/credentials/<unit>/`. | Cross-consistent with v258 unit-file analysis | 2026-08-06 |

**Injection into workload:** Quadlet units map `LoadCredentialEncrypted=`/`SetCredentialEncrypted=` directly onto the tmpfs mount. Compose-native devices map the equivalent need onto a `secrets:` file mount backed by the sealed store.

### 6.2 Podman secret drivers

| Driver | Behavior | Source |
|---|---|---|
| `file` (default) | Plaintext file, read-protected. Not encrypted at rest. Cannot be claimed as at-rest protection under Change 5. | `containers/podman` `docs/source/markdown/podman-secret-create.1.md` @ `main` |
| `shell` | Custom scripts; `SECRET_ID` via env, content via stdin/stdout. Integration point for OS-level sealing (e.g. script backed by `systemd-creds`/tpm2-tools). | Same source |
| `pass` | GPG-encrypted file. | Same source |

Verified 2026-08-07.

### 6.3 Service-manager persistence — the default-teardown trap

**Mechanism:** `loginctl enable-linger <user>`.

By default, a `--user`-scope service manager is torn down when the owning user's last session ends. `man/loginctl.xml` @ systemd v258: *"If enabled for a specific user, a user manager is spawned for the user at boot and kept around after logouts. This allows users who are not logged in to run long-running services."*

This is the trap the SUP's service-persistence MUST exists to close. An implementer with no prior exposure to rootless service managers would not discover this from the SUP's outcome-based wording alone.

Verified 2026-08-07. Perishability: MEDIUM — mechanism has been stable across many releases.

### 6.4 Runtime-scoped secrets — the single-owner destruction-hook trap

**Named example:** `ExecStopPost=`.

`man/systemd.service.xml` @ systemd v258 confirms `ExecStopPost=` commands run "as part of stopping the service" — scoped to one unit's own stop lifecycle. This is why the SUP's Change 5b prohibits reusing such a hook as the destruction trigger for a runtime-scoped secret: the hook fires on one workload's lifecycle event and cannot know whether the secret is still referenced by other workloads or the runtime itself.

A device implementing Change 5b needs to evaluate "no longer referenced" against its complete Desired State, not against any single unit's stop event.

Verified 2026-08-07. Perishability: LOW — directive semantics are long-stable.

### 6.5 Restart posture — configuration directives

**Directives:** `Restart=no` vs `Restart=always`.

`man/systemd.service.xml` @ v258 confirms `Restart=` governs whether the service manager restarts a unit after it exits, fails, or is killed. The tension: `Restart=no` keeps a credential failure visibly failed and diagnosable; `Restart=always` serves the offline-restart guarantee but turns an unsealable credential into a restart loop. This SUP does not resolve the tension — it is a device policy choice.

Verified 2026-08-07. Perishability: LOW.

### 6.6 MAC and the credential mount

On a device with MAC enforcement (e.g. SELinux in enforcing mode), the credential directory is typically mounted by the system service manager, and an unprivileged user cannot relabel it. Container relabel flags (`:z`/`:Z`) fail in this configuration.

Implementers face a trade: disable label separation for the container (reduction in confinement); run the workload at system scope (defeats the unprivileged-workload goal); or deliver the secret over a socket rather than a file.

Verified 2026-08-06 on a live SELinux-enforcing host. Perishability: HIGH — relabel-flag names and directive names drift across container-runtime versions.

### 6.7 The `host-bound` pattern — cleartext keyfile on unencrypted boot partition

**Reference pattern:** systemd's `crypttab(5)` `keyfile-timeout=` option, supporting an unlock keyfile on a separate device/partition from the encrypted volume. Where that partition is itself unencrypted, the key is recoverable by anyone with unencrypted access — this is the `host-bound` case regardless of what the disk-encryption mechanism is called.

Available since systemd **v243** (confirmed via `<xi:include href="version-info.xml" xpointer="v243"/>` in `man/crypttab.xml`).

**The network-bound alternative (Clevis + Tang):** Not treated as equivalent because NBDE requires a Tang server reachable at unlock time — exactly the connectivity the offline-restart guarantee cannot assume. This is a protocol-level property, not a version-specific fact.

Verified 2026-08-07 (third independent confirmation). Perishability: LOW.

### 6.8 MSS AuthN backend — OpenBao reference API surface

Verified against `openbao/openbao` @ `main`, 2026-08-07:

| Surface | Detail | Source |
|---|---|---|
| Client-certificate role registration | `POST /auth/cert/certs/:name` — registers CA cert under a named role. Multiple anchors (rotation overlap) map to one role per anchor. | `website/content/api-docs/auth/cert.mdx` |
| SPIFFE URI SAN matching | `allowed_uri_sans` — maps device's SPIFFE ID to a policy identity. | Same source |
| KV v2 read response shape | `{"data":{"data":{...},"metadata":{...,"version":2}}}` — byte-compatible with the SUP's retrieval contract. | `website/content/api-docs/secret/kv/kv-v2.mdx` |
| Agent caching default | Non-persistent (memory only). Agent cache is NOT the durable offline artifact — sealed file is. | `website/content/docs/agent-and-proxy/agent/caching/index.mdx` |

Perishability: MEDIUM — subject to OpenBao's own versioning.

### 6.9 Optional attestation-gated profile — rust-keylime

| Claim | Source | Verified |
|---|---|---|
| CNCF maturity tier: **Sandbox**. Accepted 2020-09-22. | `cncf/landscape` `landscape.yml` (`master` branch) | 2026-08-07 |

Perishability: HIGH — CNCF re-tiers projects periodically.

### 6.10 Privilege-drop primitives — non-systemd platforms

Change 5's privileged-decryption requirement is outcome-based and not systemd-specific. Reference primitives for other platforms:

| Platform | Primitive | Source | Verified |
|---|---|---|---|
| s6 | `s6-setuidgid` (drop before exec) / `s6-envuidgid` (drop after setup) | skarnet.org, s6 service-directory docs | 2026-08-08 |
| runit | `chpst -u <user>` — sets uid/gid, then runs target | smarden.org, `chpst(8)` | 2026-08-08 |
| OpenRC | `start-stop-daemon --chuid <user>[:<group>]` | Debian `start-stop-daemon(8)`; `OpenRC/openrc` `service-script-guide.md` | 2026-08-08 |

None carry a version-floor trap comparable to systemd's v250/v258 boundary — all are long-stable, general-purpose privilege-drop primitives.

---

## 7. Forward-compatible notes

- **PR #77 (read receipts):** If adopted, provides device-confirmed adoption of Desired State revisions. Useful for audit correlation but not a prerequisite for any normative requirement in this SUP.
- **DeviceCapabilities bisection proposal:** If the static/dynamic split lands, `secretsAtRest` migrates to a capability-scoped ProfileDefinition. Semantics unchanged.
- **PR #54 (valueFrom):** If adopted, coexists with `kind: secret` at the schema level. The MUST NOT rules in Change 2 foreclose ambiguity.
- **Quadlet profile (PR #69):** Once it defines `pointer` semantics, the deployment-profile prerequisite in Change 2 lifts automatically.
- **SUP-05:** Builds on Change 5b for OCI registry credential delivery.
- **Dynamic credential issuance:** Short-lived tokens and just-in-time certificates are a fundamentally different pattern (push vs. pull, no sealing needed, different rotation model). Named as a successor.

---

## 8. Reference implementation table

| Layer | Reference | License | Notes |
|---|---|---|---|
| MSS server | OpenBao Server | MPL 2.0, LF/OpenSSF | KV v2 engine + TLS cert auth. Wire-compatible with the single retrieval contract. |
| Device fetch | OpenBao Agent | MPL 2.0 | Auto-auth, local proxy. Agent cache is NOT the durable artifact — sealed file is. |
| Device sealing | OS-native mechanism per declared tier | — | See §6.1–6.7 above. |
| Device injection | Volatile mount or env var per deployment profile | — | See §6.1 (Quadlet), §6.2 (Podman). |
| Optional attestation | e.g. rust-keylime (Apache 2.0, CNCF Sandbox) | — | Secrets released only after attestation passes. |

**Rejected as normative basis:**

| Product | Reason |
|---|---|
| HashiCorp Vault | BUSL 1.1 — incompatible with LF open-standard embedding |
| Sealed Secrets (Bitnami) | Ciphertext in manifests — violates reference-only rule |
| ESO / CSI Secrets Store | Kubernetes-tethered |
| hawkBit DDI | No KV/TPM mapping |
| AGPL managers (Infisical CE, Bitwarden Unified) | Copyleft risk |
| flightctl | Coupled to fleet model (design reference, not drop-in) |

**Licensing note:** MPL 2.0 is file-level weak copyleft; embedding unmodified OpenBao Agent requires no source disclosure of integrator's own code. Route to IP Counsel before product commitment.

---

*This document is non-normative. The ballot text is `sup-04-secret-delivery.md`.*
