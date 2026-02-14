# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-14

### Added

- `ghost-init` command to generate shell interception logic for Bash/Zsh.
- Automated blocking for `pip install` and `uv pip install`.
- `textwrap.dedent` implementation to ensure shell-safe formatting.

### Fixed

- Resolved Bash syntax error where `eval` failed due to incorrect indentation in the generated shell function.
- Prevented infinite loops in shell functions by using the `command` prefix.

## [0.1.0] - 2026-02-14

### Added

- Initial project structure using `src` layout.
- `pyproject.toml` configuration for professional packaging and CLI entry points.
- Core `checker_logic` module with PyPI JSON API integration for age-gating.
- CLI entry point `ghost` for manual package verification.
- Support for `uv` package manager and PEP 668 compliance.

### Fixed

- Resolved `ModuleNotFoundError` by correctly implementing relative imports between `checker` and `checker_logic`.

### Security

- Implemented 72-hour age-gating policy to prevent AI-package hallucination attacks (Slopsquatting).
