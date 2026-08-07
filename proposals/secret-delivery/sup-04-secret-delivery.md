# WG-PROPOSAL-04: Margo Secrets Delivery — Reference-Based Secret Distribution with OpenBao Reference Implementation

| Field | Value |
|---|---|
| Date | 2026-08-07 |
| Category | Cat 2 -- normative enhancement |
| Affects | New Margo Secrets Service role, `application-description` / `application-deployment` (Parameter extension), device-side storage requirements, DeviceCapabilities |
| Depends on | **MIAF identity model (SPIFFE X.509-SVID, mTLS) — the sole normative authentication binding for this SUP.** Approved (stage P3, Decision Gate 2) in `margo/specification-enhancements` via PR #38 and its sibling PR #58 (WFM Identity Profile). Spec-text integration into `margo/specification` is tracked in PR #194, **open** as of this revision. |
| Supersedes | WG-PROPOSAL-04 Rev 1 (mechanism unchanged; makes MIAF the sole normative binding, corrects the rootless-scope requirement, broadens the at-rest taxonomy, adds revocation layering, makes residue-zero testable) |
| Status | Rev 2 -- coalition draft, pre-submission |

## Changes in Rev 2 (informative)

Rev 2 is the product of implementing Rev 1. A five-module reference lab built the mechanism end to end on a Fedora/Podman/systemd device; the requirements below are the ones that only became visible by building it, plus corrections to Rev 1 text that assumed facts no longer true.

| # | Change | Why |
|---|---|---|
| 1 | Rootless decryption rewritten as an outcome, not a mechanism | Rev 1's rule mandated a `systemd` ≤ 257 workaround as if it were a security requirement. On ≥ 258 the workaround is unnecessary and adds attack surface. |
| 2 | `secretsAtRest` broadened to four threat-keyed tiers | Rev 1's three values forced a non-TPM secure element to mis-declare, and forced a legacy no-TPM/no-FDE device to either overclaim or be locked out of every secret. |
| 3 | Service-manager persistence added as an explicit MUST | A device can satisfy every sealing rule and still fail the offline-restart MUST on a power cycle, for a reason unrelated to sealing. |
| 4 | Residue-zero made testable — enumerated surfaces, positive-control requirement | Rev 1 stated the outcome with no surfaces and no completion semantics. A destruction claim nobody can fail is not a requirement. |
| 5 | Revocation layering stated explicitly | MIAF specifies no OCSP/CRL for X.509-SVIDs. This SUP's grant revocation is the only fast lever in the stack, and Rev 1 never said so. |
| 6 | RFC 9421 fallback bound to Margo's existing replay-defense profile | Rev 1 named the fallback without parameters. Margo already has an integrated profile; a second one would drift. |
| 7 | Runtime-scoped secrets introduced (Change 5b) | A registry credential is consumed by the runtime at pull time, before the workload unit exists. Rev 1's injection model has no unit to name. |
| 8 | "Ratified" removed throughout | Margo's process defines no such state. The terminal SUP state is **Approved** at stage P3. |
| 9 | **A MUST was relaxed, deliberately: Rev 1's requirement that a non-TPM device implement OS-level FDE is removed.** Rev 2 mandates *honest declaration* of whatever posture the device has (`software`, `host-bound`, or `none`) and pushes the "is this posture acceptable for this secret" decision to WFM scheduling policy, which Change 6's tiers now let it express. A device that would previously have had to fake `software` conformance — an immutable read-only rootfs with no writable partition to encrypt, say — may now honestly decline sealing and declare `none`. | Direct consequence of adding `host-bound`. Stated here explicitly because a relaxed MUST is the last thing a spec should leave a reader to discover by diffing. |
| 10 | **MIAF is now the sole normative binding**; RFC 9421 demoted from co-equal "fallback binding" to a deprecated, sunsetting compatibility profile that cannot claim least-privilege conformance | Rev 1 presented the two bindings as alternatives. They are not: the AuthZ sub-contract binds grants to a SPIFFE ID, and under RFC 9421 no SPIFFE ID exists — so least privilege was undefined on the fallback path. Separately, PR #58 (Approved, P3) removes RFC 9421 from the Management Interface entirely. |

## Dependency Note

Transport security and client authentication rest on the MIAF mTLS/X.509-SVID channel, per the MIAF identity model (SPIFFE Trust Domain, X.509-SVID issuance, Trust Bundle-based validation). **This is the sole normative binding for the Secret Retrieval contract.**

RFC 9421 HTTP Message Signatures over HTTPS is retained only as a **deprecated compatibility profile** for deployments that have not yet onboarded SPIFFE identity (Change 4). It is not a co-equal alternative, and this SUP does not treat the two as interchangeable: the least-privilege authorization contract binds grants to a SPIFFE ID, and the compatibility profile establishes a device principal of a different kind (see Change 4) for which this SUP defines no equivalent contract. Conformance claims MUST state which of the two was used, and a claim made under the compatibility profile MUST state that least-privilege authorization was not in force.

> Editorial note — the transition, stated plainly. MIAF and the WFM Identity Profile are **Approved (P3)** in `specification-enhancements` but are **not yet integrated as normative text** in `margo/specification`. A device or WFM implementing today's `margo/specification` HEAD has no mTLS/X.509-SVID mechanism available to it — RFC 9421 HTTP Message Signatures, per the Margo Management Interface's existing security profile, remains the only client-authentication binding present in integrated spec text. This SUP's normative binding therefore becomes exercisable against integrated spec text only once PR #194 (or a successor integration PR) merges. An implementation adopting it today does so against the Approved `specification-enhancements` proposal text directly — a legitimate SUP-to-SUP dependency, but distinct from "the specification."
>
> The consequence is a genuine, temporary bind: **"implementable against integrated spec text today" and "aligned with the Approved identity model" are currently mutually exclusive**, because the only integrated client-auth mechanism is the one the Approved WFM Identity Profile removes (`proposals/wfm-identity-profile.md:267` — the `PayloadSignature` scheme "is removed"; WFMs "MUST reject requests authenticated via `PayloadSignature` with `401 Unauthorized`"). **That removal is scoped to the Margo Management Interface by the profile's own structure, not by inference:** its §1 "Scope and Structure" partitions the SUP into a general WFM identity profile and a separate Management Interface update — the latter described as "replacing RFC 9421 HTTP Message Signatures with mTLS… Specified in §7" — and the removal clause sits inside §7, "Application to the Margo Management Interface." The MSS is a distinct interface, so this SUP's compatibility profile is not a contradiction of that removal — but it plainly runs against the direction of travel, and this SUP declines to pretend otherwise. That is why RFC 9421 is retained here as a sunsetting compatibility profile rather than as a binding of equal standing.
>
> This SUP MUST NOT describe MIAF, or any SUP, as "ratified" — Margo's documented process defines no such state. The correct terms are **Approved** (P3, `specification-enhancements`) and **integrated** (merged into `margo/specification`).

## Motivation

Rev 0 established the pattern: **references travel in deployments; values travel over an authenticated pull channel; devices seal values at rest**. Rev 1 answered the build-vs-adopt question. A state-of-the-art survey of open-source implementations (OpenBao/Vault, SPIRE-layered brokers, flightctl, Keylime, hawkBit, ESO, Sealed Secrets, SOPS+age) concludes that the pattern already exists in production-grade form: **OpenBao** (MPL 2.0, Linux Foundation / OpenSSF governance, the community fork of BUSL-relicensed Vault) provides mTLS certificate authentication capable of validating SPIFFE X.509-SVIDs, a versioned KV REST API, conditional-fetch semantics, and an edge agent in a 30–55 MB footprint compatible with 256–512 MB devices.

Rev 2 answers a third question: what does the contract look like once someone has actually built it? Several requirements below exist because a reference implementation satisfied every rule in Rev 1 and still had a defect.

Margo standardizes on contracts, not products. This SUP therefore defines a **Margo Secrets Service (MSS) role** — mirroring the MIS role pattern from MIAF PR2, where conformance is judged by behavior, not by product — and profiles a minimal API contract that OpenBao satisfies out of the box. OpenBao is the **named reference implementation**; any service meeting the role's requirements conforms.

## Reference Implementation Statement (informative)

| Layer | Reference implementation | License | Notes |
|---|---|---|---|
| Server (MSS role) | OpenBao Server | MPL 2.0, LF/OpenSSF | KV v2 engine + TLS cert auth method |
| Device fetch | OpenBao Agent (auto-auth, local proxy, response cache) | MPL 2.0 | ⚠ static KV secrets are NOT persisted by the agent cache by default — the sealed credential file (below) is the durable offline artifact, not the agent cache |
| Device sealing | `systemd-creds` — **systemd ≥ v254 for system-scope sealing; systemd ≥ v258 where secrets are delivered into rootless / user-scope containers** (see Change 5) | LGPL (systemd) | ⚠ A device vendor reading only "v254" and deploying rootless will hit a silent credential-unsealing failure at unit start. The rootless floor is v258, and rootless is the common case for an unprivileged OT workload. |
| Device injection | Quadlet `LoadCredentialEncrypted=` / `SetCredentialEncrypted=` → tmpfs `/run/credentials/<unit>/` | — | Compose-native devices map to `secrets:` file mounts backed by the sealed store |
| Optional attestation-gated profile | rust-keylime (CNCF Incubating, 12–20 MB) | Apache 2.0 | Secrets released only after TPM PCR/IMA attestation passes — optional enhancement, not baseline |

Rejected as normative basis: HashiCorp Vault (BUSL 1.1 — incompatible with LF-standard embedding), Sealed Secrets (embeds ciphertext in manifests — violates reference-only rule), ESO/CSI Secrets Store (Kubernetes-control-plane-tethered), hawkBit DDI (no KV reference mapping or TPM sealing), AGPL-licensed managers (Infisical CE, Bitwarden Unified — copyleft risk for device vendors). flightctl's `platform/secret` provider (Apache 2.0) is architecturally aligned and noted as a second viable server-side basis, but its coupling to the flightctl fleet model makes it a design reference rather than the drop-in.

> Licensing gate: MPL 2.0 is file-level weak copyleft; embedding the unmodified OpenBao Agent requires no source disclosure of the integrator's own code, but formal clearance follows the standard open-source review path (route to IP Counsel before any product commitment).

## Proposed Changes

### Change 1: The Margo Secrets Service (MSS) role

The MSS is a **role, not a specific service** (same construction as the MIS role in MIAF PR2). Within a deployment, the MSS is responsible for:

- storing secret values addressed by opaque references;
- serving the Secret Retrieval contract (Change 3) over the authenticated binding;
- enforcing least-privilege authorization (Change 4); and
- versioning secrets so devices can poll for rotation cheaply.

Anything meeting these responsibilities fills the role: an OpenBao server, a WFM-embedded secrets store, or a broker in front of an existing enterprise vault. The MSS MAY be operated by the WFM vendor, the end customer, or a third party; the trust consequence (the MSS holds plaintext) MUST be documented by the operator.

### Change 2: `Parameter` extension — `secretRef` (unchanged from Rev 0)

```yaml
parameters:
  - name: cloud-tenant-key
    kind: secret
    secretRef: factory-a/eh-tenant-key
    targets:
      - pointer: CLOUD_TENANT_KEY
        components: ["cloud-gateway"]
```

- `kind: secret` MUST carry `secretRef`, MUST NOT carry a literal `value`.
- Secret values MUST NOT appear in manifests, ApplicationDeployment YAMLs, bundles, `margo-params.env`, status reports, or logs.
- **Compatibility:** `Parameter` instances with no `kind` slot present are treated as `kind: value` (today's existing literal-value behavior, unchanged). This SUP introduces `kind` as an optional discriminator; no existing conformant `Parameter` document is invalidated.
- **Format:** `secretRef` MUST match `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)*$` (lowercase path-like segments, no leading/trailing separators, no `..` traversal). This bounds the reference namespace and avoids path-traversal or collision ambiguity in MSS backends that map `secretRef` onto filesystem-like key paths.

### Change 3: Secret Retrieval contract (profiled for KV-v2 compatibility)

To let implementations deploy OpenBao unmodified as the MSS, the v1 contract adopts the KV v2 read shape as its wire profile:

```https
GET /v1/secret/data/{secretRef}
```

| Aspect | Requirement |
|---|---|
| Response body | JSON object containing at minimum `data.data` (the secret key-value map) and `data.metadata.version` (monotonic integer). Additional KV v2 metadata MAY be present and MUST be ignored if unrecognized. |
| Rotation polling | The device treats `data.metadata.version` as the change token. Implementations SHOULD support conditional fetch (`If-None-Match` on an ETag derived from version, `304` on match); where the MSS does not, the device compares the version field after fetch. **Rotation is device-detected via this signal** — a device does not re-seal spontaneously, and the re-seal/re-inject obligation in Change 5 is triggered by observing a version change here. |
| Caching | Responses MUST NOT be stored unencrypted by any intermediary or client cache (`Cache-Control: no-store`). The durable local artifact is exclusively the sealed credential file (Change 5). |
| Errors | `404` unknown ref; `403` unauthorized; problem-detail bodies per RFC 9457 where the MSS is Margo-native (informative for OpenBao-backed deployments, which return Vault-style errors — devices MUST key behavior on status code, not body shape). |

A Margo-native MSS MAY additionally expose the Rev 0 route (`GET /api/v1/secrets/{secretRef}`) as an alias; the KV-v2 profile above is the conformance target.

> **Open WG decision (unresolved as of Rev 2):** the KV-v2 wire shape above is currently the *sole mandatory* conformance target for the Secret Retrieval contract; the Margo-native route is MAY-level only. This means any MSS implementation — not just OpenBao — must emulate OpenBao/Vault's specific JSON envelope (`data.data`, `data.metadata.version`, Vault-style unspecified error bodies) to conform. This is a legitimate, pragmatic design choice, but it should be named accurately: this is a de facto Vault/OpenBao wire-format mandate with a Margo-native option, not a pure behavior-only role contract (unlike the MIS role it is modeled on). The WG must explicitly decide between:
> (a) **own it** — state plainly that this SUP mandates a Vault/OpenBao-compatible wire profile as the v1 baseline, informative Margo-native alternative notwithstanding; or
> (b) **invert priority** — define a thin Margo-native JSON envelope as the primary conformance target, with the KV-v2 shape specified as a named, negotiable compatibility profile (e.g., via `Accept` header or capability flag) that a device MAY use, so OpenBao is genuinely one of several conformant backends rather than the reference wire format.
> This decision is out of scope for this revision to make unilaterally and MUST be resolved by WG discussion before approval.

### Change 4: Authentication and authorization

- **AuthN (sole normative binding):** mTLS with X.509-SVID per the MIAF identity model. Reference mapping: OpenBao's TLS certificate auth method validates the client chain against the Trust Domain's Trust Bundle CAs (per PR #194 (open), `system-design/specification/identity/trust-bundle-and-discovery.md`); the SPIFFE ID URI SAN identifies the device principal. A conformant MSS MUST support this binding.

- **MSS trust-anchor currency (MUST):** the MSS, as a verifier of MIAF X.509-SVIDs, MUST keep its configured trust-anchor set current with the Trust Domain's published Trust Bundle, refreshing at an interval no looser than the bundle's `spiffe_refresh_hint` (or an operator-configured interval where no hint is published). A Trust Bundle rotation that removes a compromised anchor MUST reach the MSS's own trust-anchor configuration within that interval. An MSS that does not keep its trust-anchor set current re-admits a revoked issuing authority at exactly the interface — secret retrieval — this SUP exists to protect, defeating the Trust Domain's only anchor-level revocation path.

  - *Reference mapping, multi-anchor (informative):* OpenBao's TLS certificate auth method configures one CA certificate per named role (`POST /auth/cert/certs/:name`) and accepts a login that chains to *any* configured role's CA. A Trust Bundle carrying more than one current anchor — for example during a trust-anchor rotation overlap — maps to one OpenBao role per anchor, not to a single role reused across anchors.

- **RFC 9421 compatibility profile (deprecated, sunsetting).** A deployment that has not yet onboarded SPIFFE identity MAY authenticate to the Secret Retrieval contract using RFC 9421 HTTP Message Signatures over HTTPS. This is a transition accommodation, not a binding of equal standing, and it carries the following requirements:

    | Aspect | Requirement |
    |---|---|
    | Replay defense | Requests MUST follow the replay-defense profile already normative for the Margo Management Interface (`api-requirements-and-security.md`): the `created` signature parameter MUST be present, and the MSS MUST reject a request whose `created` timestamp falls outside a configurable validity window (the Management Interface's own reference value is five minutes) or in the future beyond a bounded clock-skew allowance. This SUP does not define a second, distinct RFC 9421 profile. |
    | Authorization | A deployment operating on this profile **MUST NOT claim conformance to the least-privilege authorization contract below.** That contract binds grants to a device's SPIFFE ID; this profile establishes a principal of a different kind — a Client-ID resolving to a pre-registered X.509 certificate — for which this SUP defines no entity-mapping, revocation-ordering, or trust-anchor-currency contract. Whatever authorization the MSS applies under this profile is outside this SUP's contract and MUST be documented by the operator. |
    | Sunset | A device MUST migrate to the normative mTLS/X.509-SVID binding once its Trust Domain is reachable and an SVID has been issued to it. An MSS MAY refuse this profile by policy at any time, and SHOULD refuse it once its deployment's Trust Domain is operational. |
    | Direction of travel | Implementers are put on notice that the Approved WFM Identity Profile removes RFC 9421 from the Margo Management Interface and requires WFMs to reject it with `401 Unauthorized`. That removal does not bind the MSS interface, but this profile is expected to be withdrawn from a future revision of this SUP rather than carried indefinitely. |

- **AuthZ:** the MSS MUST return a secret only to a device whose **current Desired State references that `secretRef`** (least-privilege by manifest).
  - ⚠ Honest implementation flag: vanilla OpenBao authorizes via path-based policies, not manifest awareness. Conformant OpenBao-backed deployments therefore require **policy synchronization glue** built by the WFM. This glue MUST conform to the following minimal sub-contract, so that independent WFM implementations remain interoperable at the boundary that matters — the resulting authorization state — without Margo mandating a full policy language:

    | Aspect | Requirement |
    |---|---|
    | Path grammar | Policy grants MUST be exact-match only, one grant per `secretRef` currently present in the device's Desired State. Glob/prefix wildcards MUST NOT be used to satisfy this contract (operators MAY layer broader local policy outside this contract, at their own risk). |
    | Entity mapping | Each device principal (identified by its SPIFFE ID per the MIAF identity model) MUST map to exactly one MSS-side policy identity (e.g., one OpenBao entity). The mapping MUST be deterministic and stable across manifest updates for the same device. **This sub-contract presupposes the normative mTLS/X.509-SVID binding.** This SUP does not define an equivalent entity-mapping, revocation-ordering, and trust-anchor-currency contract for any other binding. A deployment authenticating by other means — including the RFC 9421 compatibility profile below, which *does* establish its own device principal (a Client-ID resolving to a pre-registered X.509 certificate, per the Margo Management Interface's existing profile) but no SPIFFE-ID-based one — cannot satisfy this row as written, and MUST NOT claim it does. |
    | Grant ordering | Policy grants for a `secretRef` MUST be applied, and confirmed applied, before the WFM marks the corresponding Desired State update as delivered to the device. A device MUST NOT receive a manifest referencing a secret it is not yet authorized to fetch. |
    | Revocation ordering | When a `secretRef` is removed from a device's Desired State, the corresponding policy grant MUST be revoked before, or atomically with, the WFM marking that Desired State update as delivered. Revocation MUST be synchronous — eventual/best-effort revocation MUST NOT be used to satisfy this contract, since it creates a window of over-privilege that undermines the least-privilege property this contract exists to provide. |

    This is real integration work — it MUST NOT be glossed as "OpenBao does this natively."
  - Retrieval events MUST be logged by the MSS (audit), correlated to the device principal, `secretRef`, and secret version retrieved.

> **Security consideration — what "revoked" means here.** This Change's synchronous-revocation requirement operates entirely at the **authorization** layer: it governs whether a device holding a currently-valid X.509-SVID may still fetch a given `secretRef`. It does **not** revoke the SVID itself. MIAF specifies no online revocation check for X.509-SVIDs — no OCSP, no CRL; a compromised SVID is withdrawn only by removing its Trust Domain's trust anchor or by the SVID's own (short) lifetime expiring, both of which are fleet-wide and slow relative to a single-device incident. MIAF's own security model treats local, per-verifier authorization as the primary control against a stolen or misused credential in that interval.
>
> This Change's synchronous `secretRef`-grant revocation is therefore not a redundant control layered on top of SVID revocation. For the window between a suspected device compromise and that device's SVID expiring or its trust anchor rotating out, **it is the only mechanism in this stack that can immediately stop that device from retrieving secrets it is no longer trusted to hold.** Implementers MUST NOT read this Change's "revocation" as SVID revocation: a compromised device's SVID remains cryptographically valid throughout.

### Change 5: Device-side storage, injection, and destruction

| Rule | Level |
|---|---|
| No secret plaintext on any world/group-readable path, ever. Conformance testing of this property MUST cover the surfaces enumerated under *Residue-zero* below, and MUST distinguish expected runtime-injected files (e.g. the network-identity files a container runtime writes at startup) from workload-caused writes, by measuring a per-image startup baseline before judging the property. | MUST |
| Devices with a hardware root of trust MUST seal secrets at rest, binding secret availability to that root of trust, and MUST inject them such that decrypted plaintext exists only in a volatile, container-scoped mount. *(Reference: `systemd-creds encrypt --tpm2-device=auto` producing a `.cred` file; injection via `LoadCredentialEncrypted=` on a Quadlet unit, decrypted payload in tmpfs `/run/credentials/<unit>/`. Any mechanism satisfying the binding and volatility properties conforms.)* | MUST |
| Devices without a hardware root of trust MUST declare their actual at-rest posture per Change 6 — `software` where key material is not recoverable from the storage medium alone, `host-bound` where it is, `none` where no sealing is performed. A device MUST NOT declare a tier stronger than the protection it provides. *(This replaces Rev 1's requirement that a non-TPM device implement OS-level FDE specifically. The relaxation is deliberate and is recorded in "Changes in Rev 2", item 9.)* | MUST |
| A container runtime's native secret-injection mechanism MUST NOT be claimed as at-rest protection unless that mechanism is documented by its maintainer to encrypt secret content at rest. Where it is not — e.g. Podman's `file` secret driver, which stores plaintext on disk — the runtime's shell/exec-based secret sourcing MAY serve as the integration point to an OS-level sealing mechanism instead (e.g. Podman's `shell` driver invoking a `systemd-creds` / tpm2-tools backend). | MUST NOT / MAY |
| **Privileged decryption (normative, outcome-based).** Decryption of a sealed secret MUST be performed by a component holding the privilege or hardware access the sealing mechanism requires — never by the unprivileged process that ultimately consumes the plaintext. This is a property of the **decryption path**, not of where the workload container runs. *(Non-normative illustration: on `systemd` ≥ 258 this property is satisfied automatically for `--user`-scope Quadlet units — `SetCredentialEncrypted=` / `LoadCredentialEncrypted=` in a rootless unit is decrypted via the `systemd-creds.socket` Varlink service, socket-activated by PID 1 into a short-lived root-privileged `systemd-creds@.service` instance, for both host-key and TPM-key encrypted credentials. No system-scope unit and no manual plaintext hand-off is required or recommended. On `systemd` < 258, per-user service managers cannot decrypt encrypted credentials at all; a device on that floor MUST either raise its `systemd` version or decrypt in a system-scope unit and deliver the plaintext to the rootless workload over a channel the operator has independently secured — a compatibility path for a lower version floor, not a recommended architecture.)* | MUST |
| A workload's unprivileged service-manager instance MUST be configured to persist across the invoking session and to start at boot without operator presence, independently of and in addition to any credential-sealing guarantee. *(Reference: on `systemd`, `loginctl enable-linger <user>` for the account running the rootless workload.)* A device's credentials can be perfectly sealed and re-injectable and the offline-restart MUST below will still fail if this precondition is unmet. | MUST |
| Rotation: on version change observed per Change 3's change token, re-seal and re-inject; restart semantics follow the component type's update verb. | MUST |
| **Residue-zero on workload removal (normative, testable).** On workload removal, ALL of the following MUST be free of secret plaintext, verified by a conformance check **that is capable of failing** rather than one that merely asserts success: (1) the durable sealed artifact; (2) any volatile credential-delivery mount, checked *after* removal, proving the mount was destroyed rather than merely emptied; (3) the container runtime's writable/overlay layer for the removed instance; (4) the runtime's underlying image/content store; (5) the service manager's other per-session runtime state for that workload; (6) the unit or manifest definition retained on disk — ciphertext or a reference only, plaintext MUST NOT appear; (7) the system/service log sink, bounded to the operation's time window, where **an empty log window MUST be treated as an inconclusive check, not a pass**. A conformance test for this property SHOULD demonstrate, via a positive control, that it can detect a deliberately planted plaintext residue on each surface it claims to cover. | MUST |
| Offline behavior: a device MUST be able to (re)start its workloads using the last sealed credentials without MSS connectivity, subject to the service-manager persistence requirement above. The sealed credential artifact — not any agent response cache — is the durable artifact (see the agent caching caveat in the Reference Implementation Statement). | MUST |

**Scope of the residue-zero guarantee.** The MUST above is scoped to reachable, unprivileged-visible state. Swapped or freed kernel memory pages are out of reach for an unprivileged audit; deletion unlinks rather than overwrites disk blocks; another user's or root's runtime state is invisible to a rootless audit by construction. Disk-block overwrite and swap encryption are device-hardening choices outside a software conformance test's reach and are addressed under Security Considerations, not by this MUST.

**Sealing invalidation on update (mechanism-agnostic).** This SUP intentionally does not mandate TPM or any specific attestation stack — `secretsAtRest: hardware` covers TPM-based sealing as one instance of a broader class: any mechanism that binds secret availability to a verifiable device or platform state (TPM PCR values, secure boot measurements, or an equivalent attestation-derived key release policy). If a device uses such a mechanism, and a platform update changes the state the sealing is bound to, the device's update orchestration MUST ensure one of the following before the state transition completes:

1. re-encryption of all sealed secrets under the post-update state, verified successful prior to committing the transition, with rollback if re-sealing fails; or
2. the sealing policy is bound to a state predicate stable across the specific class of update being performed (e.g., a signed platform-identity claim rather than raw boot-order-sensitive measurements), such that the update does not invalidate sealed material at all.

Devices declaring `secretsAtRest: software` or `host-bound` (no verifiable-state binding) are unaffected by this clause — their key availability does not depend on measured boot state. In no case MUST a device reach a state where its sealed secrets are unrecoverable and the device cannot reach the MSS to re-fetch plaintext, as a direct consequence of a platform update. This is a normative property of *any* state-bound sealing mechanism a device chooses to implement, not a TPM-specific rule; the `systemd-creds`/TPM reference above is one conformant way to satisfy it, not the only one.

### Change 5b: Runtime-scoped secrets

Change 5 assumes the consumer of a secret is a workload container that already exists as a unit, and that injection means "into that unit's volatile credential mount." Some secrets are consumed by the **container runtime itself**, before any workload unit exists — an OCI registry credential needed at image-pull time being the motivating case (see WG-PROPOSAL-05).

A **runtime-scoped secret** is one whose consumer is the device's container runtime or service manager rather than a deployed workload. Such a secret:

| Rule | Level |
|---|---|
| MUST satisfy every sealing, declaration, and destruction requirement of Change 5 without exception. The at-rest taxonomy of Change 6 is agnostic to what a secret authorizes. | MUST |
| MUST be sealed, decrypted, and placed where the consuming runtime will read it **before** that runtime attempts the operation the secret authorizes — for a registry credential, before the image pull, which is strictly earlier in the lifecycle than "before the workload starts." | MUST |
| MAY be injected into a device-wide or namespace-wide credential store belonging to the runtime (e.g. an `auth.json`-equivalent) rather than a unit-scoped volatile mount, since no consuming unit exists at the time of use. Where it is, the destruction requirement of Change 5 applies to that store. | MAY |
| Destruction or re-sealing of a runtime-scoped secret held in a device-wide or namespace-wide store MUST be triggered by (a) the corresponding Change 4 revocation-ordering event — the `secretRef` is removed from every Desired State that referenced it — or (b) superseding rotation per Change 3's version signal, whichever applies. **Change 5's own trigger, "on workload removal," has no referent for a secret with no owning workload and MUST NOT be read as satisfied by any single workload's removal** while other workloads, or the runtime itself, still depend on the secret. Because a runtime-scoped secret may have more than one current referrer, a device implementing this MUST evaluate "no longer referenced" against its **complete current Desired State**, not by reacting to a single workload's removal event, and MUST NOT reuse a single-owner destruction hook (such as a per-unit `ExecStopPost=`) as this trigger without first confirming that no other current referrer exists. | MUST |
| Rotation of a runtime-scoped secret MUST be treated as affecting every future operation that secret authorizes, device-wide, until re-sealing completes — not as a single-parameter update. A rotation failure on a runtime-scoped secret SHOULD be surfaced with severity comparable to an offline-behavior fault. | MUST / SHOULD |

**Mapping Change 5's residue-zero surfaces onto a device-wide store.** Surfaces (3) and (5) of Change 5's residue-zero list are phrased per removed workload instance — the runtime's writable/overlay layer *for the removed instance*, and the service manager's per-session state *for that workload* — and have no referent for a secret with no owning instance. For a runtime-scoped secret they are satisfied instead by auditing the consuming runtime's own device-wide or namespace-wide credential store and any runtime-internal cache of it. The remaining five surfaces apply unchanged.

> **Open WG decision:** this subclass may alternatively be defined by WG-PROPOSAL-05 itself, cross-referencing Change 5's sealing and destruction MUSTs and adding only the ordering requirement. It is placed here because the ordering and rotation-blast-radius properties are general to *any* secret the runtime consumes, not specific to registries — but the structural choice belongs to the WG.

### Change 6: DeviceCapabilities — `secretsAtRest`

Permissible values: `hardware` | `software` | `host-bound` | `none`. **The tiers are keyed on the threat each posture actually resists, not on the mechanism used** — a mechanism-keyed enum forces devices to mis-declare, which is worse than a coarse one.

| Value | Meaning | Resists |
|---|---|---|
| `hardware` | Secret release is bound to a hardware root of trust that ordinary OS-level file access cannot extract — a TPM 2.0 (SRK-bound, optionally PCR-bound), a discrete secure element, or an equivalent attestation-backed key-release mechanism. A device declaring `hardware` MAY additionally declare an informative `sealingMechanism: tpm2 \| secure-element \| other`. A hardware root of trust sealing a *disk-encryption* key rather than the secret itself — e.g. a TPM-sealed FDE key — is still `hardware`: the tier follows the ultimate root of protection, not the payload. | Extraction of key material by a host-level attacker; disk imaging |
| `software` | Key material is **not recoverable from the storage medium alone** — e.g. full-disk encryption unlocked by an operator passphrase, or a network-bound unlock that retrieves the key from off-device. | Disk imaging / theft of powered-off storage |
| `host-bound` | The secret is encrypted to a device or machine identity, but the key material resides on the same storage medium as the ciphertext (e.g. host-key `systemd-creds` encryption with no FDE). Recoverable by anyone with unencrypted access to the device's storage. | Exfiltration of the sealed artifact *in isolation* from its host — a leaked backup, a mis-committed unit file, an artifact intercepted in transit |
| `none` | No sealing claim. | — |

Notes:

- The top tier is generalized beyond TPM 2.0 specifically so that a device with a non-TPM secure element is not forced to either mis-declare `tpm2` or under-declare `software`. This is consistent with Change 5's sealing-invalidation clause, which is already written mechanism-agnostic on the same basis.
- **The tier is determined by where the effective unlock secret lives, never by the name of the encryption mechanism.** An FDE unlock secret stored in cleartext on the same device — including in a separate unencrypted boot partition, a pattern `systemd`'s own `crypttab` format has supported natively since v243 via `keyfile-timeout=` for a key file residing on a different device — is `host-bound`, not `software`, however the disk-encryption mechanism is labelled. This is the pattern most likely to appear on a device with neither a TPM nor reliable network connectivity at boot, because the alternative unattended-unlock approach — network-bound disk encryption (Clevis + Tang / NBDE) — requires exactly the network reachability this SUP's offline-restart guarantee cannot assume. It deserves the explicit warning because its mechanism name invites the wrong declaration from the implementer most likely to need the tier.
- `host-bound` exists because collapsing it into `software` overclaims (an attacker with the disk image holds both ciphertext and key) while collapsing it into `none` under-claims and would lock a legitimate legacy device out of every secret-bearing parameter — including, under WG-PROPOSAL-05, its own registry credential.
- A `software` or `host-bound` declaration MUST NOT be presented, in any conformance claim or deployment document, as protection against a compromised or physically-open **running** host.
- WFMs SHOULD refuse to schedule `kind: secret` parameters onto `none` devices, and MAY apply finer per-secret policy across the other tiers (e.g. permitting a registry credential on `host-bound` while requiring `software` or `hardware` for a database credential). Such policy is outside this SUP's scope; the taxonomy exists to make it expressible.
- `none` remains a conformant DeviceCapabilities declaration under this SUP's hardware-optional posture. It MUST still satisfy Change 5's universal "no secret plaintext on any world/group-readable path" MUST, which binds regardless of the declared value. `none` describes the absence of a state-bound sealing mechanism, not a licence to relax file-permission hygiene.
- Devices using the attestation-gated profile MAY additionally declare `attestation: keylime`.

**Hardware-optional posture.** A device with no TPM and no secure element is not, on that basis, out of conformance with this SUP. It declares `software` or `host-bound` honestly and is scheduled with open eyes. No MUST in Change 5 is conditioned on the presence of a hardware root of trust without an explicit alternative alongside it, and the privileged-decryption, service-manager-persistence, and residue-zero requirements are hardware-agnostic by construction — they depend only on privilege separation and on filesystem and log surfaces that exist on any device.

### Alternative conformance profile (informative, unchanged): Sealed Parameters

SOPS + age end-to-end encryption inside the existing Parameter path for air-gapped or WFM-untrusted deployments. Survey confirmation: SOPS is a file format, not a service — no pull API, no rotation daemon — which is exactly why it remains the *complement* (trust minimization) rather than the baseline (fleet operations).

## Conformance Impact

| RFC 2119 | Statement |
|---|---|
| MUST | `kind: secret` Parameters carry `secretRef`, never a literal value; values absent from all manifests, params, status, logs. |
| MUST | MSS serves the KV-v2-profiled retrieval contract only over an authenticated binding, and MUST support the normative mTLS/X.509-SVID binding. |
| MUST | MSS keeps its trust-anchor set current with the Trust Domain's published Trust Bundle. |
| MUST NOT | A deployment on the deprecated RFC 9421 compatibility profile claims conformance to the least-privilege authorization contract — that contract has no device principal without a SPIFFE ID. |
| MUST | Where the compatibility profile is used, requests carry `created` and are rejected outside the validity window, per the Management Interface's existing profile; the device migrates to mTLS once its Trust Domain is reachable. |
| MUST | Least-privilege-by-manifest authorization, with WFM-driven policy synchronization where the MSS backend is path-policy-based; grant revocation synchronous. |
| MUST | Sealing at rest where a hardware root of trust is present; honest `secretsAtRest` declaration in every case; no tier declared stronger than the protection provided. |
| MUST | Decryption performed by a component holding the required privilege — never by the unprivileged consumer of the plaintext. |
| MUST | Unprivileged service-manager instance persists across sessions and starts at boot. |
| MUST NOT | A runtime's native secret mechanism claimed as at-rest encryption where its maintainer does not document at-rest encryption; unencrypted client/intermediary caching of responses. |
| MUST | Sealed credentials are the sole durable offline artifact; workload restart offline succeeds from them. |
| MUST | Residue-zero on workload removal across the seven enumerated surfaces, verified by a check capable of failing. |
| MUST | Runtime-scoped secrets available to the consuming runtime before the operation they authorize. |

## Security Considerations

- The MSS holds plaintext; operators rejecting this trust boundary use the sealed-parameter profile.
- **Revocation layering.** This SUP's revocation is authorization-layer only and does not revoke a device's SVID. MIAF specifies no OCSP or CRL for X.509-SVIDs. See the security consideration under Change 4 — during a single-device incident, this SUP's grant revocation is the only immediate control available.
- **`software` and `host-bound` are honest declarations, not degraded ones**, but their limits are narrow and must travel with any conformance claim: neither protects a compromised or physically-open running host, where whatever access reads the sealed blob typically also reaches the key that unseals it. `host-bound` additionally does not protect against whole-storage imaging. This SUP does not rank FDE variants against one another — where the FDE unlock key is held matters enormously, and that is an operator documentation obligation under Change 1's existing precedent.
- **Mandatory access control and the credential mount.** On a device with MAC enforcement (e.g. SELinux in enforcing mode), the credential directory is typically mounted by the *system* manager, and an unprivileged user cannot relabel it — the usual container relabel flags fail. Implementers face a real trade among disabling label separation for the container (a genuine, named reduction in confinement, generally not scopable to the credential mount alone), running the workload at system scope (which defeats the unprivileged-workload goal), or delivering the secret over a socket rather than a file. This SUP does not mandate a resolution, but an implementer who has not chosen one deliberately will discover the trade on a production fleet.
- State-bound sealing (e.g. TPM PCR-bound) ties secrets to measured boot/platform state. Without explicit sequencing, a platform update that changes that state before re-sealing completes can leave a device unable to unseal its credentials and unable to reach the MSS to re-fetch plaintext (a "brick" scenario), which directly contradicts the offline-restart guarantee this SUP requires. Change 5's sealing-invalidation clause exists specifically to close this hazard; implementers MUST treat it as a hard ordering dependency in update orchestration, not an optional recommendation.
- **Restart posture is a real tension this SUP does not resolve.** `Restart=no` keeps a credential failure visibly failed; `Restart=always` serves the offline-restart guarantee but turns an unsealable credential into a restart loop. Device policy, not spec text — flagged because a reference implementation must choose, and the choice is not obvious.
- **The two weak postures correlate, and WFM policy should reason about the combination.** A device's `secretsAtRest` tier and its Change 4 authentication binding are formally independent declarations — nothing in Change 5 or Change 6 depends on which binding a device uses, and a device on the compatibility profile has a fully coherent path through both. But in a real fleet they correlate: a device without a hardware root of trust is disproportionately likely to also be on the RFC 9421 compatibility profile, because both reflect the same underlying fact — an older device predating recent identity and sealing capability rollouts, arriving together in a fleet's modernisation sequence rather than independently. WFM scheduling policy SHOULD therefore reason about the combination rather than each axis alone: a secret placed on a `host-bound` or `none` device that is *also* on the compatibility profile has no cryptographic assurance on either axis, which is a materially different risk from either weakness by itself.
- **The compatibility profile has a principal, but not the one this contract is written against.** The RFC 9421 compatibility profile is *not* principal-less: it authenticates via a Client-ID resolving to a pre-registered X.509 certificate, proven by message signature, per the Margo Management Interface's own profile. What it lacks is a SPIFFE ID under MIAF's Trust Domain / Trust Bundle lifecycle, which is what this SUP's least-privilege entity-mapping row is written against — and, concretely, the named reference implementation's TLS certificate auth backend has no native equivalent for mapping a Client-ID / message-signature identity to a policy entity the way it does for a SPIFFE URI SAN (`allowed_uri_sans`); supplying one would require a separate proxy or custom auth plugin this SUP does not specify. The consequence is real — a deployment on this profile sits outside the least-privilege contract, and the synchronous-revocation lever described above does not exist for it — so operators MUST NOT treat time on this profile as security-neutral. But implementers MUST NOT read that authorization gap as evidence that RFC 9421 cannot carry a device identity in principle; the WFM Identity Profile's own roadmap contemplates an HTTP message-signature profile keyed to the X.509-SVID, so this is today's integration boundary, not a permanent architectural one.
- Retrieval metadata (who fetched what, when) is intentionally observable and audited.
- Clock skew affects the RFC 9421 compatibility profile and SVID validity; time sync SHOULD be maintained.

## Alternatives Considered

| Alternative | Verdict |
|---|---|
| HashiCorp Vault as reference impl | Rejected — BUSL 1.1 incompatible with embedding in an LF open standard ecosystem; OpenBao is the same lineage under MPL 2.0/LF governance |
| SPIRE Server + custom Go REST broker | Viable wrap; rejected as baseline because it rebuilds KV storage, versioning, and policy that OpenBao ships; remains the natural path if MIAF PR3 mandates SPIRE anyway — revisit then |
| flightctl `platform/secret` provider | Architecturally aligned (SecretRef → systemd credentials, Apache 2.0); design reference, not drop-in — coupled to the flightctl fleet model rather than the Margo Management Interface |
| Keylime attestation-gated delivery | Adopted as optional enhancement profile, not baseline — requires live verifier connectivity, conflicting with the offline-restart MUST |
| Kubernetes-origin controllers (ESO, CSI Secrets Store) | Rejected standalone — control-plane-tethered; ESO retained as design reference for the reference/fetch/inject split |
| Mechanism-keyed `secretsAtRest` enum (Rev 1's `tpm2 \| software \| none`) | Rejected in Rev 2 — a mechanism-keyed enum has no honest slot for a non-TPM secure element, and none for a legacy device with neither TPM nor FDE. Threat-keyed tiers let every device declare something true. |
| Co-equal dual binding, mTLS **or** RFC 9421 (Rev 1's framing) | Rejected in Rev 2 — the two are not substitutable. The authorization contract binds grants to a SPIFFE ID, which the RFC 9421 path does not produce, so "either binding" silently meant "least privilege on one path and undefined on the other." Retained as a deprecated, sunsetting compatibility profile with its authorization limits stated. |
| Drop RFC 9421 entirely, MIAF-only | Considered and not adopted for this revision. It is the cleaner end state and the direction PR #58 sets, but it would leave deployments with no conformant path until PR #194 merges, since MIAF is not in integrated spec text today. The sunset clause is intended to reach the same destination without stranding the transition. Revisit at the revision following PR #194's merge. |

## References

- OpenBao (openbao.org) — KV v2 API, TLS certificate auth, Agent; MPL 2.0, LF/OpenSSF
- MIAF identity model — SPIFFE X.509-SVID, Trust Domain, Trust Bundle validation. Approved (P3) in `specification-enhancements` PR #38; spec-text integration in `margo/specification` PR #194 (**open**), `system-design/specification/identity/trust-bundle-and-discovery.md`
- Margo WFM Identity Profile — Approved (P3), `specification-enhancements` PR #58, `proposals/wfm-identity-profile.md:267` (removal of the `PayloadSignature` / RFC 9421 scheme from the Margo Management Interface; `401 Unauthorized` on receipt)
- Margo Management Interface — `system-design/specification/margo-management-interface/api-requirements-and-security.md` (RFC 9421 replay-defense profile)
- systemd-creds(1); `LoadCredentialEncrypted=` / `SetCredentialEncrypted=`; systemd NEWS for v258 (per-user encrypted credentials via the `systemd-creds.socket` Varlink service). Podman secret drivers (`shell`)
- rust-keylime (CNCF Incubating); RFC 9110/7232 (conditional requests), RFC 9421, RFC 9457
- Compose Specification `secrets` element; WG-PROPOSAL-00/-05

---

*Prepared by Andrii Melashchenko (Belden Inc.), 2026-08-01; Rev 2 2026-08-07. Rev 2 supersedes Rev 1. Subject to the Open Web Foundation Contributor License Agreement governing the Margo specification.*
