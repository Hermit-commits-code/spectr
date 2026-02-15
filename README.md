# 👻 Ghost: Heuristic Supply Chain Defense

**Ghost** is a zero-trust security gatekeeper for Python developers. It intercepts `pip` installations to analyze package metadata for behavioral anomalies _before_ they touch your environment.

## 🛡️ Why Ghost?

Traditional security tools rely on databases of _known_ vulnerabilities (CVEs). Ghost focuses on **Zero-Day Heuristics**—detecting the patterns of an attack before the package is even flagged by the community.

### Key Defense Layers

- **The 72-Hour Rule**: Automatically flags any package released within the last 3 days.
- **Reputation Engine**: Detects "Inflated Trust" (High download counts on brand-new packages).
- **Velocity Tracking**: Identifies automated "Release Spraying" behavior.
- **Typosquatting Detection**: Uses Levenshtein distance to catch "look-alike" package names.
- **Integrity Protection**: Uses SHA-256 signing to ensure the tool's config haven't been tampered with.

---

## 🚀 Quick Start

### 1. Installation

```bash
pip install dependency-ghost
```

### 2. The Ghost Hook (Highly Recommended)

Enable the seamless protection layer. This adds an alias so Ghost automatically guards your installs.

```bash
ghost --install-hook
source ~/.bashrc  # or ~/.zshrc
```

### 3. Usage

Now, simply use pip-install instead of pip install:

```bash
pip-install requests

```

## ⚙️ Configuration & Hardening

Ghost stores your trusted packages in a hardened whitelist located at ~/.ghost-whitelist.

To prevent malware from silently whitelisting itself, Ghost maintains a cryptographic signature of your config. If you manually edit your whitelist, you must re-authorize it:

```bash
ghost --sign
```

## 📖 Deep Dive

For a detailed breakdown of the attack patterns Ghost is designed to stop, see our [CASE_STUDY.md](./CASE_STUDY.md).

## 🤝 Contributing

## Ghost is built for the community. If you have ideas for new heuristics or find a "Zero-Day" pattern I missed, please open an Issue or a PR

---

Maintained by: [Joseph Chu](https://github.com/Hermit-commits-code)
