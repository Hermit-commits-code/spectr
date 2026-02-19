from typing import Dict, Any
from .adapter import Adapter
from skopos.config import load_config


class SnykAdapter:
    """Placeholder Snyk adapter — disabled by default.

    Real implementations MUST be opt-in and require an API key in config.
    """

    def __init__(self):
        cfg = load_config()
        self.enabled = cfg.get("integrations", {}).get("snyk", {}).get("enabled", False)
        self.api_key = cfg.get("integrations", {}).get("snyk", {}).get("api_key", "")

    def is_enabled(self) -> bool:
        return bool(self.enabled and self.api_key)

    def enrich(self, package_name: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        # Placeholder: return empty enrichment to avoid network calls when disabled
        if not self.is_enabled():
            return {}
        # Real network calls would go here (not implemented in scaffold)
        return {"snyk": {"vulnerabilities": []}}
