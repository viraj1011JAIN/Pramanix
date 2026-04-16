# Security Policy

## Supported Versions

| Version  | Supported          |
| -------- | ------------------ |
| `0.8.x`  | ✅ Current — full security support |
| `0.7.x`  | ⚠️ Critical fixes only (90-day window from 0.8.0 release) |
| `< 0.7`  | ❌ End-of-life — please upgrade to 0.8.x |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

We follow a **coordinated / responsible disclosure** model:

1. **Email** your report to **security@pramanix.dev** (GPG key available on
   [keys.openpgp.org](https://keys.openpgp.org/) — fingerprint published in
   `/docs/security.md`).

2. **Include** in your report:
   - A clear description of the vulnerability.
   - The affected component(s) and version(s).
   - A minimal proof-of-concept or reproduction steps.
   - The potential impact (CIA triad: Confidentiality / Integrity /
     Availability).
   - Whether you believe a CVE assignment is appropriate.

3. **We will acknowledge** your email within **2 business days**.

4. **Triage SLA** — we will complete an initial severity assessment within
   **5 business days** of acknowledgement and communicate our findings.

---

## Disclosure SLA

| CVSS Score | Severity | Fix Target     | Public Disclosure |
| ---------- | -------- | -------------- | ----------------- |
| 9.0–10.0   | Critical | 7 calendar days | After patch ships |
| 7.0–8.9    | High     | 14 calendar days | After patch ships |
| 4.0–6.9    | Medium   | 30 calendar days | 90 days from report |
| 0.1–3.9    | Low      | 60 calendar days | 90 days from report |

We will never request an embargo longer than **90 days** from the date of
initial report without your explicit agreement.

---

## CVE Coordination

We request CVE identifiers through **MITRE** or a delegated CNA.  If you have
already requested a CVE, please share the identifier with us so we can
reference it in our advisory.  We will credit you in the advisory unless you
prefer to remain anonymous.

---

## Scope

The following areas are **in scope** for vulnerability reports:

- `src/pramanix/` — core SDK (guard, solver, validator, worker, translator)
- `src/pramanix/primitives/` — built-in policy primitives
- `src/pramanix/helpers/` — serialisation helpers
- Python ≥ 3.11 compatibility surface
- All published Docker images (`ghcr.io/pramanix/pramanix-*`)

The following are **out of scope** (unless you believe the impact is
significant):

- Theoretical issues with no practical exploit path.
- Issues in example code under `examples/` (not intended for production use
  verbatim).
- Issues requiring physical access to the host machine.
- Social engineering attacks against Pramanix maintainers.
- Open redirects or similar low-impact web issues in documentation sites.
- DOS attacks requiring more than 1 Gbps of traffic or equivalent compute.

---

## Threat Model Summary

Pramanix's formal threat model (STRIDE analysis, T1–T7) is documented in
[`docs/security.md`](docs/security.md).  Reviewers are encouraged to read
that document before searching for vulnerabilities, as it describes all known
attack surfaces and their mitigations.

Key trust boundaries:

| Boundary | What crosses it | Integrity mechanism |
|---|---|---|
| LLM translator → validator | Raw LLM text output | Injection scoring + Pydantic strict mode |
| Validator → Z3 solver | Typed Pydantic model instance | Type system + per-call Context isolation |
| Solver → host process (async-process mode) | `multiprocessing` IPC dict | HMAC-SHA256 sealed envelope (`_EphemeralKey`) |
| Host process → caller | `Decision` object | Immutable `frozen=True` Pydantic model |

---

## Out-of-Band Severity Escalation

If we do not respond within the triage SLA above, or if you believe the
vulnerability is being exploited actively in the wild, please escalate by
opening a **private security advisory** at:

```
https://github.com/virajjain/pramanix/security/advisories/new
```

GitHub will route this directly to repository maintainers regardless of email
delivery issues.

---

## Hall of Fame

We thank the following researchers for responsibly disclosing security issues:

*(None yet — be the first!)*

---

## Legal

We will not pursue legal action against security researchers who:

- Act in good faith.
- Avoid accessing, modifying, or deleting data beyond what is necessary to
  demonstrate the vulnerability.
- Do not disclose the vulnerability publicly before the agreed embargo ends.
- Do not perform automated scanning or DOS attacks against production systems.

We consider good-faith security research a valuable contribution to the
security of the ecosystem. Thank you.
