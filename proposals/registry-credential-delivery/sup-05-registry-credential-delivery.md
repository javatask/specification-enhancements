# Registry Credential Delivery

## Owner

[@javatask](https://github.com/javatask) — Andrii Melashchenko, Belden Inc.

## Field summary

| Field | Value |
|---|---|
| Revision | 1 |
| Stage | Draft — pre-submission |
| Anchor issues | `margo/specification` #15, #129 (device-side half) |
| Depends on | SUP-04 (Secret Delivery) — MSS role, Secret Retrieval contract, Change 5b |
| Submission | Coupled package — submitted jointly with the next SUP-04 revision |
| Companion | `sup-05-rationale-and-alternatives.md` (non-normative) |

---

## Summary

A Margo device pulls from registries twice: once for the component artifact named by an `ApplicationDescription`'s `repository`, and again for each container image named inside the resulting deployment profile document. Margo defines no way to deliver credentials for either.

This proposal defines a **`RegistryCredential`** — a per-endpoint credential resource the WFM provisions to a device independently of any application deployment. Credential material is referenced, never carried inline, and resolves through SUP-04's Secret Retrieval contract.

## Motivation

Private registries are unusable under Margo today. Both device-side pulls require anonymous read access, or out-of-band device provisioning Margo does not describe — a hard barrier to commercially distributed applications.

A registry credential cannot be carried by SUP-04's `kind: secret` Parameter mechanism: a `Parameter` addresses a location inside the deployment profile document, and the component-artifact credential would have to be written into a document the device cannot yet obtain. It is also, per SUP-04 Change 5b, a **runtime-scoped secret** with no consuming workload. The full argument, the rejected alternatives, and a worked production case are in the non-normative companion.

## Scope

**In scope:** the resource declaring a device's credential for a registry endpoint; credential selection; ordering relative to both pull operations; lifecycle, by reference to SUP-04.

**Out of scope:** how credential material reaches the WFM (the intake half of issue #129); the Application Registry ↔ WFM path, already addressed in integrated text; registry-side authorization policy; token minting or other credential issuance.

## Affected files

| File | Change |
|---|---|
| `system-design/specification/registry-credentials/` (new) | Defines the `RegistryCredential` resource, selection, and ordering |
| `system-design/specification/applications/application-description.md` | Adds OPTIONAL `requiredRegistries` |
| `system-design/specification/margo-secrets-service/` (SUP-04) | Referenced, not modified |

---

## Change 1: The `RegistryCredential` resource

A resource published by the WFM to a device independently of any `ApplicationDescription`.

```yaml
apiVersion: margo.org/v1
kind: RegistryCredential
metadata:
  name: <name>
spec:
  endpoint: <registry-host>
  secretRef: <secretRef>
```

| Field | Requirement |
|---|---|
| `endpoint` | REQUIRED. The registry host this credential authenticates to. MUST be a host, optionally with a port. MUST NOT include a scheme, repository path, tag, or digest. |
| `secretRef` | REQUIRED. Resolved through SUP-04's Secret Retrieval contract. MUST NOT carry inline credential material. |

A device MUST treat the resolved data object as opaque credential material for the named endpoint, and MUST NOT require any particular key naming to conform.

A `RegistryCredential` MUST NOT be embedded in, or scoped to, an `ApplicationDescription`.

## Change 2: Credential selection

A device performing a registry pull MUST select the `RegistryCredential` whose `endpoint` matches the registry host of that pull, and MUST use no other.

- Matching MUST be on the full host, compared case-insensitively.
- A device MUST NOT match by suffix, prefix, or wildcard.
- Where no `RegistryCredential` matches, the device MUST attempt the pull unauthenticated. A missing credential is not, by itself, a failure.

## Change 3: Resolution and ordering

A device MUST resolve a matched `RegistryCredential`'s `secretRef` and make the resulting material available to its container runtime **before** initiating the pull that requires it. This obligation applies independently to the component-artifact pull and to each container-image pull.

Sealing, privileged decryption, at-rest declaration, and residue-zero obligations are those of SUP-04 Changes 5 and 5b without variation. Two consequences of Change 5b are restated because they are load-bearing here:

- The material MAY be placed in a device-wide or namespace-wide credential store belonging to the runtime. Where it is, SUP-04's destruction requirement applies to that store.
- Destruction or re-sealing MUST NOT be triggered by any single workload's removal. It is triggered when no remaining Desired State references the `RegistryCredential`, or by superseding rotation.

SUP-04's locator-based injection contract governs delivery to a workload and has no referent here. A device satisfies this Change by making the material available to its runtime through whatever mechanism that runtime consumes, subject to Changes 5 and 5b in full.

## Change 4: Declared registry dependencies (OPTIONAL)

An `ApplicationDescription` MAY declare the registry endpoints its deployment requires:

```yaml
spec:
  requiredRegistries:
    - <registry-host>
```

- A WFM MAY use this to avoid scheduling an application onto a device with no matching `RegistryCredential`.
- A device MUST NOT use it to constrain credential selection; Change 2 is the sole selection rule.
- A device MUST NOT refuse a pull because its endpoint is absent from this list.

## Change 5: WFM ordering

A WFM MUST publish a `RegistryCredential`, and MUST have written its credential material to the MSS, before publishing any Desired State whose deployment requires that endpoint.

This is a WFM-internal sequencing rule, testable without device cooperation. It carries no confirmation semantics and no WFM-to-MSS protocol obligation.

---

## Conformance impact

| Actor | Obligation |
|---|---|
| Device | Consume `RegistryCredential`; exact-host selection; resolve before pull, both pull types; attempt unauthenticated on no match; SUP-04 Changes 5/5b in full |
| WFM | Publish `RegistryCredential`; write material to the MSS before dependent Desired State; MAY use `requiredRegistries` |
| MSS | None new — registry credentials are ordinary `secretRef`s |
| Application developer | None required; MAY declare `requiredRegistries` |

Devices deploying only from public registries remain conformant with no `RegistryCredential` present.

## Backward compatibility

Additive. `RegistryCredential` is a new resource; `requiredRegistries` is a new OPTIONAL field. No existing `ApplicationDescription` is invalidated and no working deployment changes behaviour.

## Security considerations

1. **Blast radius is per endpoint by design.** A compromised device's credential grants whatever the registry grants for that endpoint. Operators SHOULD provision least-privilege per-device or per-site registry accounts where the registry supports them. Margo cannot enforce this.
2. **Exact-host matching is a security requirement.** Suffix or wildcard matching would permit a credential to be presented to a host the operator never authorised.
3. **A device-wide credential store is a wider surface than a workload-scoped one.** A device MUST NOT treat a runtime's native credential store as at-rest protection unless that store is documented by its maintainer to encrypt content at rest.
4. **Rotation has device-wide effect.** The runtime MUST be permitted to proceed on the currently-sealed value until re-sealing completes, and MUST NOT block or queue operations meanwhile.
5. **Revocation inherits SUP-04's posture.** Material already sealed on the device remains usable until the `RegistryCredential` leaves Desired State and destruction runs. This is inherent to offline-capable devices; it is named, not closed.
6. **Registry endpoints are not secret.** `endpoint` and `requiredRegistries` are ordinary configuration and MAY appear in status reports and logs. Only resolved material is sensitive.

## References

- `margo/specification` issues #15, #129
- SUP-04 Secret Delivery — MSS role, Secret Retrieval contract, Change 5b
- WG-PROPOSAL-01 — Compose OCI packaging and Component Registry storage
- OCI Distribution Specification v1.1.0
- `sup-05-rationale-and-alternatives.md` — non-normative companion
