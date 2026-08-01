# WG-PROPOSAL-04: Margo Secrets Delivery — Reference-Based Secret Distribution with OpenBao Reference Implementation

| Field | Value |
|---|---|
| Date | 2026-08-01 |
| Category | Cat 2 -- normative enhancement |
| Affects | New Margo Secrets Service role, `application-description` / `application-deployment` (Parameter extension), device-side storage requirements, DeviceCapabilities |
| Depends on | MIAF identity model (SPIFFE X.509-SVID, mTLS) — assumed ratified for this revision |
| Supersedes | WG-PROPOSAL-04 Rev 0 (mechanism unchanged; adds contract profiling and reference implementation) |
| Status | Rev 1 -- coalition draft, pre-submission |

## Dependency Note

Transport security rests on the MIAF mTLS/X.509-SVID channel, per the ratified MIAF identity model (SPIFFE Trust Domain, X.509-SVID issuance, Trust Bundle-based validation). This is the **primary binding**. For deployments that have not yet onboarded SPIFFE identity, RFC 9421 HTTP Message Signatures over HTTPS is the **fallback binding** (transit confidentiality via TLS, weaker mutual auth than SVID-based mTLS). Conformance claims MUST state the binding used.

> Editorial note: this revision assumes the MIAF identity model referenced above is ratified. If, at the time of submission, the specific MIAF document defining SVID issuance and Trust Bundle validation is still in draft, this SUP's ratification MUST be gated on that document's ratification — SUP-04 MUST NOT carry MUST-level normative text whose primary binding depends on an unratified specification. This note should be removed once MIAF's status is confirmed at submission time.

## Motivation

Rev 0 established the pattern: **references travel in deployments; values travel over an authenticated pull channel; devices seal values at rest**. Rev 1 answers the build-vs-adopt question. A state-of-the-art survey of open-source implementations (OpenBao/Vault, SPIRE-layered brokers, flightctl, Keylime, hawkBit, ESO, Sealed Secrets, SOPS+age) concludes that the pattern already exists in production-grade form: **OpenBao** (MPL 2.0, Linux Foundation / OpenSSF governance, the community fork of BUSL-relicensed Vault) provides mTLS certificate authentication capable of validating SPIFFE X.509-SVIDs, a versioned KV REST API, conditional-fetch semantics, and an edge agent in a 30–55 MB footprint compatible with 256–512 MB devices.

Margo standardizes on contracts, not products. This SUP therefore defines a **Margo Secrets Service (MSS) role** — mirroring the MIS role pattern from MIAF PR2, where conformance is judged by behavior, not by product — and profiles a minimal API contract that OpenBao satisfies out of the box. OpenBao is the **named reference implementation**; any service meeting the role's requirements conforms.

## Reference Implementation Statement (informative)

| Layer | Reference implementation | License | Notes |
|---|---|---|---|
| Server (MSS role) | OpenBao Server | MPL 2.0, LF/OpenSSF | KV v2 engine + TLS cert auth method |
| Device fetch | OpenBao Agent (auto-auth, local proxy, response cache) | MPL 2.0 | ⚠ static KV secrets are NOT persisted by the agent cache by default — the sealed credential file (below) is the durable offline artifact, not the agent cache |
| Device sealing | `systemd-creds` (systemd ≥ v254 recommended), TPM 2.0 SRK/PCR binding | LGPL (systemd) | |
| Device injection | Quadlet `LoadCredentialEncrypted=` → tmpfs `/run/credentials/<unit>/` | — | Compose-native devices map to `secrets:` file mounts backed by the sealed store |
| Optional attestation-gated profile | rust-keylime (CNCF Incubating, 12–20 MB) | Apache 2.0 | Secrets released only after TPM PCR/IMA attestation passes — optional enhancement, not baseline |

Rejected as normative basis: HashiCorp Vault (BUSL 1.1 — incompatible with LF-standard embedding), Sealed Secrets (embeds ciphertext in manifests — violates reference-only rule), ESO/CSI Secrets Store (Kubernetes-control-plane-tethered), hawkBit DDI (no KV reference mapping or TPM sealing), AGPL-licensed managers (Infisical CE, Bitwarden Unified — copyleft risk for device vendors). flightctl's `platform/secret` provider (Apache 2.0) is architecturally aligned and noted as a second viable server-side basis, but its coupling to the flightctl fleet model makes it a design reference rather than the drop-in.

> Licensing gate: MPL 2.0 is file-level weak copyleft; embedding the unmodified OpenBao Agent in BeldenOS requires no source disclosure of Belden code, but formal clearance follows the standard open-source review path (route to IP Counsel before any product commitment).

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
| Rotation polling | The device treats `data.metadata.version` as the change token. Implementations SHOULD support conditional fetch (`If-None-Match` on an ETag derived from version, `304` on match); where the MSS does not, the device compares the version field after fetch. |
| Caching | Responses MUST NOT be stored unencrypted by any intermediary or client cache (`Cache-Control: no-store`). The durable local artifact is exclusively the sealed credential file (Change 5). |
| Errors | `404` unknown ref; `403` unauthorized; problem-detail bodies per RFC 9457 where the MSS is Margo-native (informative for OpenBao-backed deployments, which return Vault-style errors — devices MUST key behavior on status code, not body shape). |

A Margo-native MSS MAY additionally expose the Rev 0 route (`GET /api/v1/secrets/{secretRef}`) as an alias; the KV-v2 profile above is the conformance target.

> **Open WG decision (unresolved as of Rev 1):** the KV-v2 wire shape above is currently the *sole mandatory* conformance target for the Secret Retrieval contract; the Margo-native route is MAY-level only. This means any MSS implementation — not just OpenBao — must emulate OpenBao/Vault's specific JSON envelope (`data.data`, `data.metadata.version`, Vault-style unspecified error bodies) to conform. This is a legitimate, pragmatic design choice, but it should be named accurately: this is a de facto Vault/OpenBao wire-format mandate with a Margo-native option, not a pure behavior-only role contract (unlike the MIS role it's modeled on). The WG must explicitly decide between:
> (a) **own it** — state plainly that this SUP mandates a Vault/OpenBao-compatible wire profile as the v1 baseline, informative Margo-native alternative notwithstanding; or
> (b) **invert priority** — define a thin Margo-native JSON envelope as the primary conformance target, with the KV-v2 shape specified as a named, negotiable compatibility profile (e.g., via `Accept` header or capability flag) that a device MAY use, so OpenBao is genuinely one of several conformant backends rather than the reference wire format.
> This decision is out of scope for this revision to make unilaterally and MUST be resolved by WG discussion before ratification.

### Change 4: Authentication and authorization

- **AuthN (primary binding):** mTLS with X.509-SVID per the MIAF identity model. Reference mapping: OpenBao's TLS certificate auth method validates the client chain against the Trust Domain's Trust Bundle CAs (per `identity/trust-bundle-and-discovery.md`); the SPIFFE ID URI SAN identifies the device principal. **Fallback binding:** RFC 9421 HTTP Message Signatures over HTTPS, for deployments that have not onboarded SPIFFE identity.
- **AuthZ:** the MSS MUST return a secret only to a device whose **current Desired State references that `secretRef`** (least-privilege by manifest).
  - ⚠ Honest implementation flag: vanilla OpenBao authorizes via path-based policies, not manifest awareness. Conformant OpenBao-backed deployments therefore require **policy synchronization glue** built by the WFM. This glue MUST conform to the following minimal sub-contract, so that independent WFM implementations remain interoperable at the boundary that matters — the resulting authorization state — without Margo mandating a full policy language:

    | Aspect | Requirement |
    |---|---|
    | Path grammar | Policy grants MUST be exact-match only, one grant per `secretRef` currently present in the device's Desired State. Glob/prefix wildcards MUST NOT be used to satisfy this contract (operators MAY layer broader local policy outside this contract, at their own risk). |
    | Entity mapping | Each device principal (identified by its SPIFFE ID per the MIAF identity model) MUST map to exactly one MSS-side policy identity (e.g., one OpenBao entity). The mapping MUST be deterministic and stable across manifest updates for the same device. |
    | Grant ordering | Policy grants for a `secretRef` MUST be applied, and confirmed applied, before the WFM marks the corresponding Desired State update as delivered to the device. A device MUST NOT receive a manifest referencing a secret it is not yet authorized to fetch. |
    | Revocation ordering | When a `secretRef` is removed from a device's Desired State, the corresponding policy grant MUST be revoked before, or atomically with, the WFM marking that Desired State update as delivered. Revocation MUST be synchronous — eventual/best-effort revocation MUST NOT be used to satisfy this contract, since it creates a window of over-privilege that undermines the least-privilege property this contract exists to provide. |

    This is real integration work — it MUST NOT be glossed as "OpenBao does this natively."
  - Retrieval events MUST be logged by the MSS (audit), correlated to the device principal, `secretRef`, and secret version retrieved.

### Change 5: Device-side storage, injection, and destruction

| Rule | Level |
|---|---|
| No secret plaintext on any world/group-readable path, ever. | MUST |
| TPM 2.0 devices MUST seal at rest (reference: `systemd-creds encrypt --tpm2-device=auto` → `.cred` file) and inject via credential mechanisms (`LoadCredentialEncrypted=` on Quadlet; decrypted payload exists only in tmpfs `/run/credentials/<unit>/`). | MUST |
| Non-TPM devices MUST use OS-level FDE (e.g., LUKS) and declare `secretsAtRest: software`. | MUST |
| Podman `file` secret driver alone MUST NOT be claimed as at-rest protection. Podman's `shell` secret driver MAY be used as the integration point to a `systemd-creds`/tpm2-tools backend. | MUST NOT / MAY |
| **Rootless quirk (normative):** rootless user sessions typically lack `/dev/tpmrm0` access. Credential decryption MUST occur at the system service-manager level (system-scope Quadlet unit performing `LoadCredentialEncrypted=`) before delegation to the rootless container context. | MUST |
| Rotation: on version change, re-seal and re-inject; restart semantics follow the component type's update verb. | MUST |
| On workload removal, sealed credential files, tmpfs mounts, and any agent cache entries for that workload MUST be destroyed (residue-zero). Reference: `ExecStopPost=` cleanup of the `.cred` file. | MUST |
| Offline behavior: a device MUST be able to (re)start its workloads using the last sealed credentials without MSS connectivity. The sealed `.cred` file — not any agent response cache — is the durable artifact (see agent caching caveat in the Reference Implementation Statement). | MUST |

**Sealing invalidation on update (mechanism-agnostic).** This SUP intentionally does not mandate TPM or any specific attestation stack — `secretsAtRest: tpm2` covers TPM-based sealing as one instance of a broader class: any mechanism that binds secret availability to a verifiable device or platform state (TPM PCR values, secure boot measurements, or an equivalent attestation-derived key release policy). If a device uses such a mechanism, and a platform update changes the state the sealing is bound to, the device's update orchestration MUST ensure one of the following before the state transition completes:

1. re-encryption of all sealed secrets under the post-update state, verified successful prior to committing the transition, with rollback if re-sealing fails; or
2. the sealing policy is bound to a state predicate stable across the specific class of update being performed (e.g., a signed platform-identity claim rather than raw boot-order-sensitive measurements), such that the update does not invalidate sealed material at all.

Devices declaring `secretsAtRest: software` (FDE-based, no verifiable-state binding) are unaffected by this clause — FDE key availability does not depend on measured boot state. In no case MUST a device reach a state where its sealed secrets are unrecoverable and the device cannot reach the MSS to re-fetch plaintext, as a direct consequence of a platform update. This is a normative property of *any* state-bound sealing mechanism a device chooses to implement, not a TPM-specific rule; the `systemd-creds`/TPM reference above (Reference Implementation Statement) is one conformant way to satisfy it, not the only one.

### Change 6: DeviceCapabilities — `secretsAtRest`

Permissible values `tpm2` | `software` | `none`. WFMs SHOULD refuse to schedule `kind: secret` parameters onto `none` devices. Devices using the attestation-gated profile MAY additionally declare `attestation: keylime`.

### Alternative conformance profile (informative, unchanged): Sealed Parameters

SOPS + age end-to-end encryption inside the existing Parameter path for air-gapped or WFM-untrusted deployments. Survey confirmation: SOPS is a file format, not a service — no pull API, no rotation daemon — which is exactly why it remains the *complement* (trust minimization) rather than the baseline (fleet operations).

## Conformance Impact

| RFC 2119 | Statement |
|---|---|
| MUST | `kind: secret` Parameters carry `secretRef`, never a literal value; values absent from all manifests, params, status, logs. |
| MUST | MSS serves the KV-v2-profiled retrieval contract only over the authenticated binding. |
| MUST | Least-privilege-by-manifest authorization, with WFM-driven policy synchronization where the MSS backend is path-policy-based. |
| MUST | TPM 2.0 sealing where present; FDE + `secretsAtRest: software` declaration otherwise; rootless decryption at system manager level. |
| MUST NOT | Podman `file` driver claimed as at-rest encryption; unencrypted client/intermediary caching of responses. |
| MUST | Sealed credentials are the sole durable offline artifact; workload restart offline succeeds from them. |
| MUST | Full secret residue destruction on workload removal. |

## Security Considerations

- The MSS holds plaintext; operators rejecting this trust boundary use the sealed-parameter profile.
- State-bound sealing (e.g., TPM PCR-bound) ties secrets to measured boot/platform state. Without explicit sequencing, a platform update that changes that state before re-sealing completes can leave a device unable to unseal its credentials and unable to reach the MSS to re-fetch plaintext (a "brick" scenario), which directly contradicts the offline-restart guarantee this SUP requires. Change 5's sealing-invalidation clause exists specifically to close this hazard; implementers MUST treat it as a hard ordering dependency in update orchestration, not an optional recommendation.
- Retrieval metadata (who fetched what, when) is intentionally observable and audited.
- Clock skew affects the RFC 9421 fallback binding and SVID validity; time sync SHOULD be maintained.

## Alternatives Considered

| Alternative | Verdict |
|---|---|
| HashiCorp Vault as reference impl | Rejected — BUSL 1.1 incompatible with embedding in an LF open standard ecosystem; OpenBao is the same lineage under MPL 2.0/LF governance |
| SPIRE Server + custom Go REST broker | Viable wrap; rejected as baseline because it rebuilds KV storage, versioning, and policy that OpenBao ships; remains the natural path if MIAF PR3 mandates SPIRE anyway — revisit then |
| flightctl `platform/secret` provider | Architecturally aligned (SecretRef → systemd credentials, Apache 2.0); design reference, not drop-in — coupled to the flightctl fleet model rather than the Margo Management Interface |
| Keylime attestation-gated delivery | Adopted as optional enhancement profile, not baseline — requires live verifier connectivity, conflicting with the offline-restart MUST |
| Kubernetes-origin controllers (ESO, CSI Secrets Store) | Rejected standalone — control-plane-tethered; ESO retained as design reference for the reference/fetch/inject split |

## References

- OpenBao (openbao.org) — KV v2 API, TLS certificate auth, Agent; MPL 2.0, LF/OpenSSF
- MIAF identity model — SPIFFE X.509-SVID, Trust Domain, Trust Bundle validation (`identity/trust-bundle-and-discovery.md`)
- systemd-creds(1), `LoadCredentialEncrypted=`; Podman secret drivers (`shell`)
- rust-keylime (CNCF Incubating); RFC 9110/7232 (conditional requests), RFC 9421, RFC 9457
- Compose Specification `secrets` element; WG-PROPOSAL-00/-05

---

*Prepared by Andrii Melashchenko (Belden Inc.), 2026-08-01. Rev 1 supersedes Rev 0. Subject to the Open Web Foundation Contributor License Agreement governing the Margo specification.*
