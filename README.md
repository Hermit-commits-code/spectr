# Dependency-Ghost 👻

> **Stop AI Hallucinations from becoming Supply Chain Attacks.**

Dependency-Ghost is a security wrapper for Python package managers. It intercepts installation requests and cross-references them against PyPI metadata to identify "Slopsquatting" and hallucinated packages.

## 🛡️ Governance Features

- **Age-Gating:** Blocks packages younger than 72 hours.
- **Reputation Check:** Validates download trends vs. name similarity.
- **Audit Logging:** Keeps a local ledger of every blocked/allowed install.

## 🛠️ Status

Currently in **Alpha (v0.1.0)**. Infrastructure phase.
