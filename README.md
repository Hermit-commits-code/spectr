[![PyPI version](https://img.shields.io/pypi/v/skopos-audit.svg)](https://pypi.org/project/skopos-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# 🛡️ Skopos (v0.23.0)

## Overview

The Zero-Trust Gatekeeper for your Python Environment.

Skopos (Greek for "watcher/lookout") is a high-speed forensic audit tool designed to stop supply-chain attacks before they touch your disk. It sits between you and the internet, ensuring that every `uv add` or `pip install` is safe, verified, and free of "keyword-stuffing" or "brand-jacking" attempts.

## Table of Contents

- [Overview](#overview)
- [Why Skopos?](#why-skopos)
- [Installation](#installation)
	- [For Pip users](#for-pip-users)
	- [For UV users (recommended workflow)](#for-uv-users-recommended-workflow)
- [Automatic Bouncer (Shim)](#automatic-bouncer-shim)
- [Usage & Examples](#usage--examples)
- [Performance](#performance)
- [Forensic Heuristics](#forensic-heuristics)
- [License](#license)

## Why Skopos?

Standard package managers are built for speed, not security. They assume that if a package exists on PyPI, it’s safe to run. They are wrong.

Skopos protects you from:

- **Keyword Stuffing:** Malicious packages like `requests-ultra` or `pip-security-patch`.
- **Brand-jacking:** Fake versions of popular tools (e.g., `google-auth-v2` by an unknown dev).
- **Account Hijacking:** Suddenly active projects after years of silence.
- **Obfuscated Payloads:** Detection of "packed" or encrypted code in package metadata.

## Installation

Choose the workflow that matches your environment. Both approaches are supported — pick one.

### For Pip users

If you prefer standard Python packaging and virtual environments, follow these steps.

Create and activate a virtual environment (recommended):

```bash
python -m venv .venv
source .venv/bin/activate
```

Install Skopos into the active environment:

```bash
# During development
pip install -e .

# Or install the released package
pip install skopos-audit
```

Reload your shell if you modified rc files:

```bash
source ~/.bashrc
# or
source ~/.zshrc
```

Quick verification for Pip users:

```bash
which skopos || skopos --version
```

### For UV users (recommended workflow)

If you use `uv` as your package manager, Skopos can be installed as an `uv` tool and hooked into `uv add`.

Install via `uv`:

```bash
uv tool install skopos-audit
```

After installing via `uv`, refresh `uv` so it picks up the new tool entry:

```bash
uvx --refresh skopos
```

If you still want to isolate the CLI into a virtual environment (recommended for development), create and activate one first and then install into it via `pip install -e .`.

Reload your shell and verify the CLI is available:

```bash
source ~/.bashrc || source ~/.zshrc
which skopos || skopos --version
```

## Automatic Bouncer (Shim)

The best way to use Skopos is to let it intercept your commands automatically. This adds a split-second security check whenever you try to add a new dependency.

- Locate the Shim: The script is located in `scripts/skopos-uv.sh`.
- Add to your shell (append to `~/.bashrc` or `~/.zshrc`):

```bash
alias uv='source /path/to/your/skopos/scripts/skopos-uv.sh'
```

Now, when you run `uv add <package>`, Skopos audits the package first. If the score is too high (malicious), the installation is blocked.

## Usage & Examples

You can audit any package without installing it:

```bash
skopos check requests-ultra
```

Example Output (Malicious Package):

```
🔍 Auditing: requests-ultra
------------------------------------------------------------
❌ Typosquatting: FLAG (Match: requests - Keyword stuffing)
⚠️  Identity:      Unknown (New Account / Unverified)
✅ Payload:       Clean (No obfuscation)
------------------------------------------------------------
🚨 SKOPOS SCORE: 120/100 (MALICIOUS)
🚫 Action: Installation Blocked.
```

## Performance

Is it slow? No. Version 0.23.0 removed the heavy `RestrictedPython` sandbox. Skopos now performs "Static Metadata Forensics."

- **Speed:** Checks usually take < 500ms.
- **Safety:** We never execute the code we are auditing. We analyze the "fingerprints" left on PyPI.

## Forensic Heuristics

Skopos uses a weighted scoring system to evaluate risk:

- **Name Similarity:** reqests vs requests (Levenshtein)
- **Keyword Stuffing:** requests-security-update
- **Author Reputation:** Brand new accounts uploading high-value names
- **Entropy Scan:** Encrypted or obfuscated code strings
- **Project Velocity:** "Zombie" projects that suddenly wake up

## License

MIT. Built for developers who value their ssh keys and environment variables.
