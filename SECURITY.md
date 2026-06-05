# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `1.0.x` (current dev) | ✅ |
| `< 1.0` | ❌ |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Security issues in Pramanix — a library whose entire purpose is to act as an
execution firewall for autonomous AI agents — carry higher-than-average stakes.
A vulnerability in Pramanix could allow AI agents to bypass safety constraints,
forge audit records, or execute unauthorized actions in production systems.

### Coordinated Disclosure Process

1. **Email** `virajwork1011@gmail.com` with subject line:
   `[PRAMANIX SECURITY] <short description>`

2. **Include** in your report:
   - Affected version(s) and component(s)
   - Step-by-step reproduction instructions
   - Impact assessment (what an attacker can achieve)
   - Any proof-of-concept code (redact sensitive data)

3. **Response SLA**:
   - Acknowledgement within **48 hours**
   - Triage decision within **5 business days**
   - Patch timeline communicated within **10 business days**

4. **Disclosure timeline**: We follow a **90-day coordinated disclosure** window.
   After 90 days (or upon patch release, whichever comes first) you are free to
   publish your findings.  We will credit you in the release notes unless you
   prefer to remain anonymous.

### Scope

In scope for security reports:
- Bypass of `Guard.verify()` / `Guard.verify_async()` safety decisions
- Forge or tamper with Merkle audit log records
- Execution token replay attacks
- Information disclosure from decision explanations / violated invariants
- Supply chain attacks on Pramanix dependencies
- Authentication bypass in the Agent Mesh (`MeshAuthenticator`)
- Z3 solver manipulation producing spurious `sat` results

Out of scope:
- Denial-of-service via extreme Z3 inputs (use `solver_timeout_ms`)
- Issues in the user's own policy definitions
- Vulnerabilities in user-supplied `translator` backends

### Security Contact

**Primary**: Viraj Jain — `virajwork1011@gmail.com`

### Bug Bounty

Pramanix does not currently operate a paid bug bounty program.  Researchers
who responsibly disclose valid security vulnerabilities will be credited in
`CHANGELOG.md` and the GitHub release notes.

### PGP Key

A PGP key for encrypted communication will be published at
[pramanix.dev/security](https://pramanix.dev/security) prior to the v1.0.0
General Availability release.
