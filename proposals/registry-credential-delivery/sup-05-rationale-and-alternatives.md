# Registry Credential Delivery — Rationale and Alternatives (non-normative)

## Status of this document

**This document is non-normative and carries no conformance requirements.** Nothing here may be read as constraining or extending the MUSTs, MUST NOTs, SHOULDs, or MAYs stated in `sup-05-registry-credential-delivery-normative.md` ("the SUP"). It is not put to a vote.

It exists because the SUP's design is not self-evident from its requirements. Three questions arise on any careful reading — why the existing `Parameter` mechanism cannot carry a registry credential, why credentials are scoped per endpoint rather than per application, and why the obvious alternative was rejected — and answering them inside the ballot text would triple its length without adding a single requirement.

---

## 1. The problem, precisely

Margo's Application Registry workflow is fully specified in integrated text. It is a **WFM-side** workflow: the WFM pulls the Application Package, and the resulting Desired State reaches the device over the Margo management channel. The device never touches the Application Registry.

The device touches two other registries, and neither has a credential path.

| # | Pull | Performed by | Named in | Credential path today |
|---|---|---|---|---|
| 1 | Component artifact (Helm chart, Compose Archive) | **Device** | `ApplicationDescription.repository` (an `oci://` URI) + `revision` | None |
| 2 | Container images | **Device** | The deployment profile document obtained from pull 1 | None |

Both must therefore be anonymously readable, or the device must be provisioned by a mechanism outside Margo's description. For an application vendor distributing commercially, neither is acceptable — which is the substance of issue #15.

## 2. Why `kind: secret` Parameters cannot carry this

Two independent reasons. Both matter, because a proposal addressing only the second appears to work and does not.

### 2.1 For the component-artifact credential, the injection target does not yet exist

A `Parameter` writes its resolved value to a `targets[].pointer` addressing a location **inside the deployment profile document**. That document is the content of the component artifact — the thing pull 1 fetches.

A credential needed to perform pull 1 would have to be written into a document the device cannot obtain until pull 1 succeeds. This is a genuine ordering circularity, not an implementation inconvenience, and no amount of resolution-phase ordering inside the `Parameter` model escapes it.

### 2.2 A registry credential has no workload to be injected into

SUP-04's Change 5b already establishes this. A registry credential is a **runtime-scoped secret**: its consumer is the device's container runtime, before any workload unit exists. Change 5b defines its sealing, ordering, and destruction properties precisely, and explicitly defers the delivery mechanism to this proposal.

A registry credential is therefore not a parameter of an application. It is a property of a device's relationship with a registry endpoint.

## 3. Why per endpoint

Registry authentication is per endpoint by construction: a client presents credentials to a host, and every artifact pulled from that host uses them.

| Scoping | One credential change means | Reuse across applications |
|---|---|---|
| Per application | N updates, N rotations, N revocations | None — N copies of one credential |
| **Per endpoint** | One update, one rotation, one revocation | Automatic |

Applications reference registries; they do not carry credentials for them. `requiredRegistries` (Change 4) exists so an application can express that reference for scheduling purposes without acquiring any authorization role.

**Why exact-host matching, and why it is a security requirement rather than a convenience.** Suffix or wildcard matching would let a credential provisioned for one registry be presented to another that merely shares a domain. That is a credential-disclosure path to a host the operator never authorised, and it is not hypothetical — subdomain-scoped registries are common in cloud provider offerings.

**Why a missing credential is not a failure.** Public registries are a first-class case. Requiring a `RegistryCredential` for every pull would break every currently-working anonymous deployment, for no security benefit.

## 4. Alternatives considered

### A1 — Device-scoped registry configuration, provisioned out of band

Credentials configured directly on the device by an operator or vendor tool, outside Margo entirely.

**Rejected.** It resolves the circularity, but it is what deployments do today and it is precisely the gap issue #15 asks Margo to close. It scales poorly — per-device manual provisioning across a fleet — and it puts credential lifecycle outside the WFM, so rotation and revocation have no fleet-wide path. It leaves cross-vendor interoperability exactly where it is now: undefined.

### A2 — First-reference bootstrap within the application manifest

A `kind: secret` Parameter marked for resolution ahead of image resolution, inside the same `ApplicationDescription`.

**Rejected, on structural rather than stylistic grounds.** This is the alternative a reviewer is most likely to propose independently, because it appears to work — and for pull 2 it does, since the deployment profile document exists by the time images are pulled. It fails for pull 1, where the credential would have to be written into a document the device cannot yet obtain (§2.1).

A proposal adopting A2 would close half the gap while appearing to close all of it, which is the worst available outcome: it would ship, pass review, and fail in exactly the deployments it was written for. It also strains the `Parameter` model — which addresses locations inside a deployment profile document — into carrying a value with no such location (§2.2).

### A3 — A separate credential resource published ahead of Desired State — **ADOPTED**

One mechanism serves both pulls. The circularity dissolves because the resource carries no reference into an unobtained document. Per-endpoint scoping matches how registry authentication actually works. Credential lifecycle stays with the WFM, so it scales with the fleet.

**The cost, accepted knowingly:** a new resource type, a genuine addition to Margo's surface. It is accepted because no existing resource can carry a device-scoped, application-independent property.

### A4 — Short-lived token minting

The device authenticates with its X.509-SVID to a token service that mints a registry token per pull.

**Not rejected — out of scope.** It is credential *issuance*, structurally distinct from delivery: a lease-and-TTL lifecycle rather than versioned material, and a request contract rather than a retrieval contract. It is a natural successor once a Margo credential-issuance contract exists, and it would reuse this proposal's endpoint-matching rule unchanged.

## 5. Worked case

A device vendor's edge-capable hardware hosts an application vendor's containerised sensor gateway. Sensors connect southbound; the gateway forwards northbound to the application vendor's own cloud. The end customer owns the plant and holds commercial relationships with both vendors.

The deployment requires four artifacts. Three are served by existing mechanisms and by SUP-04. The fourth — the container image, held in the application vendor's private registry — is served by nothing, and blocks the deployment entirely.

The case also illustrates why the intake half of issue #129 is deliberately out of scope. Three parties, three commercial relationships: none of them wants Margo specifying how the application vendor's registry credential is approved, issued, or rotated. That is bilateral commerce mediated by the customer's own compliance regime, and it differs for every customer the application vendor has. What all three need identically is that the credential arrives safely and is destroyed on removal.

## 6. Package coupling with SUP-04

This proposal is submitted jointly with the next SUP-04 revision and intended for review as one body of work.

**Why.** Registry credentials are the case that most sharply exercises SUP-04's runtime-scoped subclass. Change 5b was written with this consumer in mind and explicitly defers delivery here. Reviewing the two together lets the WG evaluate the subclass against its motivating case rather than in the abstract, and prevents a SUP-04 revision from being balloted with a deferred obligation whose closure nobody has yet seen.

**What it costs.** The package advances at the speed of its slower half; a WG objection to either proposal delays both.

**If the WG prefers to decouple.** This proposal stands against SUP-04 as currently drafted with modest adjustment. Nothing in its Changes depends on SUP-04's retrieval wire shape, which it never touches, and Change 3 already notes the locator-based injection contract has no referent for a runtime-scoped secret. The load-bearing dependencies — the MSS role, `secretRef` resolution, and Changes 5 and 5b — are present in SUP-04 today.

## 7. A generalization this proposal deliberately does not make

SUP-04's Change 5b defines *runtime-scoped secret* as a class. This proposal specifies one instance of that class.

A generalized `RuntimeCredential` — with a `profile` discriminator, a class-level selection rule, a class-level ordering anchor ("before the operation the credential authorizes," lifted near-verbatim from Change 5b), and `registry` as its first profile — is a natural and inexpensive future step. Other members of the class are foreseeable: artifact-signature verification material, proxy credentials, attestation-service credentials.

**Three reasons it is not made here.** A pattern is earned by two instances, and this proposal has one. A generalized framework draws framework-scale review, and this package is already carrying a substantial SUP-04 revision. And a `profile` discriminator invites comparison with the delivery-mode discriminator SUP-04 deliberately rejected — a comparison that is answerable (that discriminator selected between delivery mechanisms for one thing, with one branch strictly weaker; this one distinguishes consumers with genuinely different selection keys) but costs review time to answer.

The Changes above are written so that this generalization is a later addendum rather than a rewrite: selection, ordering, and declaration are each stated as a single rule with one endpoint-specific specialization.

## 8. Open questions for the WG

1. Should `endpoint` matching consider port when the pull uses the scheme default? *Suggested: normalise to the default port before comparison.*
2. Should more than one `RegistryCredential` be permitted for one endpoint, e.g. during rotation overlap? *Suggested: no, for determinism.*
3. Should credential-key naming be constrained for cross-vendor testability? *Suggested: leave opaque in Revision 1 and revisit if interoperability testing shows divergence.*
4. Do unit-based deployment profiles introduce a third pull class this proposal has not enumerated?

## 9. Design philosophy alignment

Each scope decision in the SUP follows from a stated principle rather than from convenience.

| Decision | Principle |
|---|---|
| Credential intake left to the WFM's own surface | Specify the contract at the interop boundary, not on both sides of it |
| Selection and ordering stated as outcomes; no runtime credential-store format named | Specify outcomes, not mechanisms |
| Missing credential is not a failure | Never require a third party to modify an artifact they already ship — public-registry deployments continue unchanged |
| Token minting named and deferred (A4) | Name every deferral, and name its successor |
