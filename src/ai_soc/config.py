"""All settings come from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # "fixture" = offline sample data, "wazuh" = live Wazuh indexer
    siem_backend: str
    fixture_dir: str
    wazuh_indexer_url: str
    wazuh_indexer_user: str
    wazuh_indexer_password: str
    wazuh_verify_tls: bool
    wazuh_ca_cert: str
    wazuh_alerts_index: str
    wazuh_events_index: str
    claude_model: str
    claude_effort: str
    max_agent_turns: int

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            siem_backend=os.getenv("SIEM_BACKEND", "fixture"),
            fixture_dir=os.getenv("FIXTURE_DIR", "fixtures/T1059_001"),
            wazuh_indexer_url=os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200"),
            wazuh_indexer_user=os.getenv("WAZUH_INDEXER_USER", "admin"),
            wazuh_indexer_password=os.getenv("WAZUH_INDEXER_PASSWORD", ""),
            # Lab Wazuh uses self-signed certs: set WAZUH_CA_CERT to its root-ca.pem rather than disabling checks.
            wazuh_verify_tls=_bool(os.getenv("WAZUH_VERIFY_TLS"), True),
            wazuh_ca_cert=os.getenv("WAZUH_CA_CERT", ""),
            wazuh_alerts_index=os.getenv("WAZUH_ALERTS_INDEX", "wazuh-alerts-*"),
            wazuh_events_index=os.getenv("WAZUH_EVENTS_INDEX", "wazuh-archives-*"),
            claude_model=os.getenv("CLAUDE_MODEL", "claude-opus-5-5"),
            claude_effort=os.getenv("CLAUDE_EFFORT", "medium"),
            max_agent_turns=int(os.getenv("MAX_AGENT_TURNS", "8")),
        )
