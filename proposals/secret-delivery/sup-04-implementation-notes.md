# Secret Delivery — Implementation Notes (non-normative)

## Status of this document

**This document is non-normative. It carries no conformance requirements.** Nothing here may be read as constraining or extending the MUSTs, MUST NOTs, SHOULDs, or MAYs stated in `sup-04-secret-delivery.md` ("the SUP"). Where a Change in the SUP points here, the pointer means exactly this: *"a reference mechanism exists, here is one, conformance is judged against the MUST in the SUP — not against this mechanism."* An implementation that satisfies the SUP's outcome-based requirements by a different mechanism than the one described here conforms just as well.

The OS- and product-version facts in this document are perishable in a way the SUP's ballot text deliberately is not. The SUP states outcomes ("decryption MUST be performed by a privileged component"); this document states one way to achieve that outcome today, with a specific tool and a specific version floor, both of which will drift. Every fact below carries its own verification date and source; **re-verify anything you plan to rely on operationally, not just anything you plan to cite in a WG discussion.**

---

## 1. Device sealing — credential encryption floor

**Reference mechanism:** `systemd-creds` — the tool, and the `LoadCredentialEncrypted=` / `SetCredentialEncrypted=` service-file directives that consume its output.

| Claim | Verification | Source | Perishability |
|---|---|---|---|
| System-scope credential sealing (the `systemd-creds` tool; `LoadCredentialEncrypted=`/`SetCredentialEncrypted=`; TPM2-bound encryption) is available from `systemd` **v250**. `systemd` NEWS "CHANGES WITH 250" introduces the `systemd-creds` tool and the `LoadCredentialEncrypted=`/`SetCredentialEncrypted=` directives directly; "CHANGES WITH 254" contains no `systemd-creds`-specific entry — its only TPM2-adjacent change that release is an SRK-binding rollout for *disk encryption* (`systemd-cryptenroll`/`systemd-cryptsetup`), a different subsystem. | Verified | `systemd/systemd` NEWS, "CHANGES WITH 250" section | HIGH — version floors of this kind drift with every `systemd` release; re-verify before relying on it operationally |
| Rootless / `--user`-scope decryption of an encrypted credential requires `systemd` **v258**. Before v258, a `--user`-scope service manager cannot decrypt an encrypted credential **at all** — host-key or TPM-bound. A device vendor reading only "v250" and deploying a rootless workload will hit a silent credential-unsealing failure at unit start. | Verified. `systemd` NEWS v258, verbatim: *"Encrypted systemd service credentials are now available for user services too, including if locked to TPM. Previously, they could only be used for system services."* | `systemd/systemd` NEWS, "CHANGES WITH 258" | HIGH |
| The rootless decryption path (v258+): a `--user`-scope unit's `LoadCredentialEncrypted=`/`SetCredentialEncrypted=` request is serviced via the `systemd-creds.socket` Varlink service — a **system-manager**-owned socket (`ListenStream=/run/systemd/io.systemd.Credentials`, `Accept=yes`) that PID 1 socket-activates into a short-lived, root-privileged `systemd-creds@.service` instance (no `User=` directive — runs as root), for both host-key and TPM-key encrypted credentials. No system-scope unit and no manual plaintext hand-off is required. This is the structural basis for the SUP's privileged-decryption requirement: the rootless unit's own unprivileged process never performs the decryption itself. | Verified against the actual unit files, not just NEWS prose. | `systemd/systemd` `units/systemd-creds.socket` + `units/systemd-creds@.service` @ tag `v258` | HIGH — re-check unit-file shape on any major version bump |
| Decrypted plaintext lands in tmpfs `/run/credentials/<unit>/`. | Carried forward from a prior verification session (2026-08-06), consistent with the v258 unit-file finding above; not independently re-derived on a live Quadlet unit this session. | Prior-session verification, cross-consistent with the Varlink finding above | HIGH |

**Injection into a workload.** Quadlet units map `LoadCredentialEncrypted=`/`SetCredentialEncrypted=` directly onto the tmpfs mount above. Compose-native devices map the equivalent need onto a `secrets:` file mount backed by the sealed store rather than a plaintext file.

---

## 2. Runtime-native secret mechanisms — traps and reference integrations

Podman's secret drivers, verified against the maintainer's own documentation:

| Driver | Behavior | Source |
|---|---|---|
| `file` (default) | Secret resides in a read-protected **plaintext** file. Not encrypted at rest. MUST NOT be claimed as at-rest protection under the SUP's Change 5. | `containers/podman` `docs/source/markdown/podman-secret-create.1.md` @ `main` |
| `shell` | Managed by custom scripts; `SECRET_ID` is passed via environment, secret content via stdin/stdout. This is the integration point a device can use to bridge to an OS-level sealing mechanism (e.g. a script backed by `systemd-creds`/tpm2-tools) — the SUP's Change 5 explicitly permits this. | Same source |
| `pass` | GPG-encrypted file. | Same source |

**Verified**, exact wording, against `containers/podman` `docs/source/markdown/podman-secret-create.1.md` @ `main`, 2026-08-07.

---

## 3. Service-manager persistence — the default-teardown trap

**Reference mechanism:** `loginctl enable-linger <user>`.

By default, a `--user`-scope service manager is torn down when the owning user's last session ends. `man/loginctl.xml` @ `systemd` v258, verbatim: *"If enabled for a specific user, a user manager is spawned for the user at boot and kept around after logouts. This allows users who are not logged in to run long-running services."* The "if enabled" phrasing confirms, by direct implication, that the default (unset) behavior tears the user manager down at logout — the trap the SUP's Change 5 persistence MUST exists to close, and a fact an implementer with no prior exposure to rootless/user-scope service managers would not independently discover from the SUP's outcome-based wording alone.

**Verified.** Source: `systemd/systemd` `man/loginctl.xml` @ v258. Perishability: MEDIUM — mechanism has been stable across many releases, low drift risk.

---

## 4. Runtime-scoped secrets — the single-owner destruction-hook trap

**Named example:** `ExecStopPost=`.

`man/systemd.service.xml` @ `systemd` v258 confirms `ExecStopPost=` commands run "as part of stopping the service" — scoped to that one unit's own stop lifecycle. This is precisely why the SUP's Change 5b prohibits reusing a hook like this as the destruction/re-sealing trigger for a runtime-scoped secret: the hook fires on one workload's own lifecycle event and has no way to know whether the secret it might destroy is still referenced by other workloads, or by the runtime itself. A device implementing Change 5b needs to evaluate "no longer referenced" against its complete Desired State, not against any single unit's stop event.

**Verified, structurally.** Source: `systemd/systemd` `man/systemd.service.xml` @ v258. Perishability: LOW — directive semantics are long-stable.

---

## 5. Restart posture — the configuration directives

**Named directives:** `Restart=no` and `Restart=always` (and the intermediate values `systemd` defines between them).

`man/systemd.service.xml` @ v258 confirms `Restart=` governs whether the service manager restarts a unit after it exits, fails, or is killed. The tension the SUP's Security Considerations name — `Restart=no` keeps a credential failure visibly failed and diagnosable; `Restart=always` serves the offline-restart guarantee but turns an unsealable credential into a restart loop instead of a single clear failure signal — follows directly from this directive's documented semantics. This SUP does not resolve the tension; it is a device policy choice.

**Verified**, directive exists as described. Source: `systemd/systemd` `man/systemd.service.xml` @ v258. Perishability: LOW.

---

## 6. Mandatory access control and the credential mount

On a device with MAC enforcement (e.g. SELinux in enforcing mode), the credential directory is typically mounted by the *system* service manager, and an unprivileged user cannot relabel it — the usual container relabel flags (`:z`/`:Z`) fail in this configuration. Implementers face a real trade: disable label separation for the container (a genuine, named reduction in confinement, generally not scopable to the credential mount alone); run the workload at system scope (which defeats the unprivileged-workload goal the SUP's Change 5 is written around); or deliver the secret over a socket rather than a file.

**Verification status: verified 2026-08-06, NOT re-run 2026-08-07.** This fact was confirmed in a prior session against a live SELinux-enforcing host; it was not re-derived against a live host or a primary SELinux/systemd source in the session that produced this revision, and no such environment was available to re-check it. Re-run the live check immediately before this document is relied on operationally, rather than treating this note as a fresh 2026-08-07 verification. Perishability: HIGH — the specific relabel-flag names and directive names (`:z`/`:Z`, `SecurityLabelDisable=`) are exactly the kind of detail that drifts across container-runtime versions.

---

## 7. The `secretsAtRest: host-bound` pattern — cleartext keyfile on an unencrypted boot partition

**Reference pattern:** `systemd`'s `crypttab(5)` `keyfile-timeout=` option, which supports an unlock keyfile residing on a separate device/partition from the encrypted volume it unlocks — a pattern that has existed since `systemd` **v243** (confirmed via the machine-readable `<xi:include href="version-info.xml" xpointer="v243"/>` marker in `man/crypttab.xml`, not free-text prose that could be misread). Where that separate partition is itself unencrypted, the unlock key is recoverable by anyone with unencrypted access to the device's storage — this is the `host-bound` case in the SUP's Change 6 taxonomy, regardless of what the disk-encryption mechanism is called.

**Verified**, third independent confirmation across this programme (a prior live-host check, an earlier agent-memory record, and a fresh fetch this session). Source: `systemd/systemd` `man/crypttab.xml` @ v258. Perishability: LOW — this fact has now survived three independent checks.

**The network-bound alternative, and why the SUP does not treat it as equivalent.** Clevis + Tang (Network-Bound Disk Encryption, NBDE) is a real, actively-maintained alternative unattended-unlock mechanism (`latchset/clevis`, confirmed live as an actively maintained project with a Tang pin at `src/pins/tang/`). It is not treated as a substitute for the cleartext-keyfile pattern above because NBDE requires a Tang server to be reachable over the network at unlock time, by construction of the protocol — exactly the connectivity the SUP's offline-restart guarantee cannot assume. This is an architectural property of NBDE, not a version-specific fact requiring separate verification. Perishability: LOW — this is a protocol-level property, not a version pin.

---

## 8. MSS AuthN backend — reference API surface (OpenBao)

Verified against OpenBao's own primary documentation, `openbao/openbao` @ `main`, 2026-08-07:

| Surface | Detail | Source |
|---|---|---|
| Client-certificate role registration | `POST /auth/cert/certs/:name` — registers a CA certificate under a named role. A Trust Bundle carrying more than one current anchor (e.g. during a rotation overlap) maps to one role per anchor, not a single role reused across anchors. | `website/content/api-docs/auth/cert.mdx` |
| SPIFFE URI SAN matching | `allowed_uri_sans` — the parameter that lets a role's client-certificate validation match against a client's SPIFFE URI SAN. This is the mechanism a path-policy-based backend uses to map a device's SPIFFE ID to a policy identity. | Same source |
| KV v2 read response shape | `{"data":{"data":{...},"metadata":{...,"version":2}}}` — confirmed byte-for-byte against the compatibility profile's documented shape in the SUP. | `website/content/api-docs/secret/kv/kv-v2.mdx` |
| Agent caching default | "Agent performs all operations in memory and does not persist anything to storage" — the default caching behavior. A distinct `persistent-caches` opt-in feature exists separately; the default is non-persistent, confirming the SUP's caveat that the agent cache is not the durable offline artifact. | `website/content/docs/agent-and-proxy/agent/caching/index.mdx` |

Perishability: MEDIUM — this is OpenBao's own API surface, independent of Margo's release cadence, but subject to OpenBao's own versioning.

---

## 9. Optional attestation-gated profile — rust-keylime

| Claim | Verification | Source |
|---|---|---|
| rust-keylime's CNCF maturity tier is **Sandbox**. Accepted 2020-09-22; most recent annual review PR (`cncf/toc` #959) dated 2022-11-10. | Verified against the live `cncf/landscape` data (`landscape.yml`, `master` branch — the same source feeding landscape.cncf.io), which lists `project: sandbox`. | `cncf/landscape` `landscape.yml` (live, `master` branch), 2026-08-07. Perishability: HIGH — CNCF re-tiers projects periodically; re-check at publication. |

No primary-source citation for rust-keylime's package size was found in the time available; no size figure is given here.

---

## Cross-reference discipline

Each affected Change in `sup-04-secret-delivery.md` carries a one-line pointer of the form:

> *"A reference mechanism satisfying this property, including any relevant version floor, is documented in the non-normative Implementation Notes companion to this SUP (`sup-04-implementation-notes.md`); conformance is judged against the MUST above, not against the referenced mechanism."*

The trailing clause is the operative part — it is what stops this document from being read as a second, competing source of normative obligation.

---

*This document accompanies `sup-04-secret-delivery.md` and has no independent standing. It is not put to a vote.*
