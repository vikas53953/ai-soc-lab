"""Where alerts and events come from.

Two interchangeable backends with the same two methods:
  - FixtureBackend: reads saved JSON files (offline, no Wazuh needed)
  - WazuhIndexerBackend: queries the live Wazuh indexer (OpenSearch)

Both return the same compact "event" shape from normalize(), so the MCP server
and the agent never know which one is behind them.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

import httpx

from ai_soc.config import Settings

MAX_FULL_LOG_CHARS = 2000

# Fields from Windows / Sysmon events worth showing the agent. Everything else is dropped
# to keep tool results small.
WIN_EVENTDATA_FIELDS = (
    "image",
    "commandLine",
    "parentImage",
    "parentCommandLine",
    "user",
    "processId",
    "parentProcessId",
    "hashes",
    "destinationIp",
    "destinationPort",
    "queryName",
    "targetFilename",
)


class SiemError(Exception):
    """Raised when an alert or event cannot be fetched."""


def _get(source: dict[str, Any], dotted: str) -> Any:
    node: Any = source
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def normalize(doc_id: str, source: dict[str, Any]) -> dict[str, Any]:
    """Turn one raw Wazuh document into the compact shape the agent sees."""
    eventdata = _get(source, "data.win.eventdata") or {}
    system = _get(source, "data.win.system") or {}
    full_log = source.get("full_log") or ""
    event: dict[str, Any] = {
        "event_id": doc_id,
        "timestamp": source.get("timestamp"),
        "host": _get(source, "agent.name"),
        "rule": {
            "id": _get(source, "rule.id"),
            "level": _get(source, "rule.level"),
            "description": _get(source, "rule.description"),
            "mitre": _get(source, "rule.mitre.id") or [],
        },
        "windows_event_id": system.get("eventID"),
        "fields": {k: eventdata[k] for k in WIN_EVENTDATA_FIELDS if eventdata.get(k) not in (None, "")},
    }
    if full_log:
        event["full_log"] = full_log[:MAX_FULL_LOG_CHARS]
    return event


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class SiemBackend(Protocol):
    def get_alert(self, alert_id: str) -> dict[str, Any]: ...

    def search_events(
        self, host: str, start: str, end: str, contains: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]: ...


class FixtureBackend:
    """Reads alerts.json and events.json from a folder. Each file is a list of
    {"_id": ..., "_source": {...}} documents, the same shape the indexer returns."""

    def __init__(self, folder: str | Path):
        self.folder = Path(folder)
        self._alerts = self._load("alerts.json")
        self._events = self._load("events.json")

    def _load(self, name: str) -> list[dict[str, Any]]:
        path = self.folder / name
        if not path.exists():
            raise SiemError(f"Fixture file not found: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        for doc in self._alerts:
            if doc["_id"] == alert_id:
                return normalize(doc["_id"], doc["_source"])
        raise SiemError(f"Alert {alert_id} not found")

    def search_events(
        self, host: str, start: str, end: str, contains: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        t0, t1 = _parse_ts(start), _parse_ts(end)
        hits = []
        for doc in sorted(self._events, key=lambda d: d["_source"]["timestamp"]):
            src = doc["_source"]
            if _get(src, "agent.name") != host:
                continue
            if not (t0 <= _parse_ts(src["timestamp"]) <= t1):
                continue
            if contains and contains.lower() not in json.dumps(src).lower():
                continue
            hits.append(normalize(doc["_id"], src))
            if len(hits) >= limit:
                break
        return hits


class WazuhIndexerBackend:
    """Queries the Wazuh indexer (OpenSearch) over HTTPS.

    Alerts live in wazuh-alerts-*. Raw events (including Sysmon events that did not
    trigger an alert) live in wazuh-archives-* only if archives are turned on;
    see lab/wazuh/README.md.
    """

    def __init__(self, settings: Settings):
        verify: bool | str = settings.wazuh_ca_cert or settings.wazuh_verify_tls
        self.settings = settings
        self.http = httpx.Client(
            base_url=settings.wazuh_indexer_url,
            auth=(settings.wazuh_indexer_user, settings.wazuh_indexer_password),
            verify=verify,
            timeout=20.0,
        )

    def _search(self, index: str, body: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            resp = self.http.post(f"/{index}/_search", json=body)
        except httpx.HTTPError as exc:
            raise SiemError(f"Cannot reach Wazuh indexer: {exc}") from exc
        if resp.status_code != 200:
            raise SiemError(f"Wazuh indexer returned {resp.status_code}: {resp.text[:300]}")
        return resp.json().get("hits", {}).get("hits", [])

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        # Wazuh puts its own alert id in the "id" field; also accept the indexer _id.
        body = {
            "size": 1,
            "query": {"bool": {"should": [{"term": {"id": alert_id}}, {"ids": {"values": [alert_id]}}]}},
        }
        hits = self._search(self.settings.wazuh_alerts_index, body)
        if not hits:
            raise SiemError(f"Alert {alert_id} not found")
        return normalize(hits[0]["_id"], hits[0]["_source"])

    def search_events(
        self, host: str, start: str, end: str, contains: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        filters: list[dict[str, Any]] = [
            {"term": {"agent.name": host}},
            {"range": {"timestamp": {"gte": start, "lte": end}}},
        ]
        query: dict[str, Any] = {"bool": {"filter": filters}}
        if contains:
            query["bool"]["must"] = [{"match_phrase": {"full_log": contains}}]
        body = {"size": min(limit, 200), "sort": [{"timestamp": "asc"}], "query": query}
        hits = self._search(self.settings.wazuh_events_index, body)
        return [normalize(h["_id"], h["_source"]) for h in hits]


def build_backend(settings: Settings) -> SiemBackend:
    if settings.siem_backend == "fixture":
        return FixtureBackend(settings.fixture_dir)
    if settings.siem_backend == "wazuh":
        return WazuhIndexerBackend(settings)
    raise SiemError(f"Unknown SIEM_BACKEND '{settings.siem_backend}' (use 'fixture' or 'wazuh')")
