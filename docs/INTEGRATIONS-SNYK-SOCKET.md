# Integrations: Snyk & Socket (scaffold)

This document outlines the planned integrations for Snyk and Socket. It is a design + scaffold placeholder; no network calls or secrets will be stored here.

Goals
- Provide optional, configurable adapters to consult external vulnerability feeds (Snyk) and real-time alerts (Socket) as enrichments for the Skopos scoring pipeline.
- Keep adapters disabled by default and require explicit configuration (API keys, enable flags) before any network activity.

Design
- `skopos.integrations` package will contain adapter interfaces and simple noop implementations.
- Config knobs in `~/.skopos/config.toml`:
  - `[integrations.snyk]` -> `enabled = false`, `api_key = ""`
  - `[integrations.socket]` -> `enabled = false`, `endpoint = ""`

Security
- Adapters must run only when `enabled = true` and a non-empty credential is present.
- All network calls SHOULD be optional and run in user-controlled contexts; CI or local runs must opt-in.

Files to add (scaffolded):
- `src/skopos/integrations/__init__.py` – package init
- `src/skopos/integrations/adapter.py` – base `Adapter` class and interface
- `src/skopos/integrations/snyk_adapter.py` – Snyk adapter (placeholder)
- `src/skopos/integrations/socket_adapter.py` – Socket adapter (placeholder)

This scaffold intentionally avoids any external dependencies. Implementations that call external APIs must be added behind feature flags and require explicit config entries.

Once you review, I'll add the placeholder files and a small unit test to ensure the integration loader does not execute network calls when disabled.
