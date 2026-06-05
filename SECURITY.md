# Security Policy

Token Core Monorepo contains wallet core code for software-wallet and
hardware-wallet integrations. Please report suspected vulnerabilities privately.

## Reporting a Vulnerability

Email vulnerability reports to `sec@token.im`.

Do not open public GitHub issues, pull requests, or discussions for suspected
security issues before the maintainers have evaluated the report.

Include as much of the following as possible:

- Affected component: `token-core`, `imkey-core`, `tcx-wasm`, mobile SDK,
  release packaging, or dependency.
- Affected version, commit, tag, or artifact.
- Description of the impact.
- Reproduction steps, proof of concept, test case, or crash log.
- Expected result and actual result.
- Whether the issue can lead to asset loss, key disclosure, signature misuse,
  address mismatch, device misuse, denial of service, or supply-chain risk.
- Suggested fix, if known.

## Scope

In scope:

- Keystore generation, import, export, encryption, decryption, and KDF behavior.
- Mnemonic, private key, seed, and derived key handling.
- Address derivation, transaction signing, message signing, and serialization.
- Chain-specific signing logic in `token-core`.
- imKey APDU command construction, transport handling, and response parsing.
- Protobuf API and C ABI behavior that can affect wallet safety.
- `tcx-wasm` behavior that can affect browser wallet safety.
- Release artifacts, dependency policy, and packaging configuration in this
  repository.

Out of scope:

- Issues that require compromising a user's device, operating system, browser,
  or account outside this repository.
- Social engineering, phishing, or support scams.
- Denial-of-service reports without a clear repository-level defect or security
  impact.
- Third-party service outages unrelated to repository code.
- Publicly known dependency vulnerabilities without a demonstrated impact on
  this repository.

## Handling

Maintainers aim to acknowledge security reports within two business days. The
time needed for triage, fix development, release, and disclosure depends on
severity and affected artifacts.

Please do not publicly disclose the issue until maintainers have completed
triage and coordinated a fix or mitigation plan.

## Additional Report

The historical imKey security report is available at
[`doc/imKeySecurityReport.pdf`](./doc/imKeySecurityReport.pdf).
