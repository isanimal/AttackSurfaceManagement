import csv
import json
from typing import List, Dict, Any


def write_json(path: str, records: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)


def _flatten_for_csv(r: Dict[str, Any]) -> Dict[str, Any]:
    dns = r.get("dns", {})
    http = r.get("http", {})
    http_http = http.get("http", {}) if isinstance(http, dict) else {}
    http_https = http.get("https", {}) if isinstance(http, dict) else {}

    def _pick_title():
        if http_https.get("alive"):
            return http_https.get("title")
        if http_http.get("alive"):
            return http_http.get("title")
        return None

    def _pick_server():
        # prefer https header
        h = (http_https.get("headers") or {}) if isinstance(http_https, dict) else {}
        if h.get("server"):
            return h.get("server")
        h2 = (http_http.get("headers") or {}) if isinstance(http_http, dict) else {}
        return h2.get("server")

    tags = r.get("tags", [])
    if isinstance(tags, list):
        tags_str = ",".join(tags)
    else:
        tags_str = ""

    return {
        "domain_input": r.get("domain_input"),
        "subdomain": r.get("subdomain"),
        "a": ";".join(dns.get("a", []) or []),
        "aaaa": ";".join(dns.get("aaaa", []) or []),
        "http_alive": bool(http_http.get("alive")),
        "http_status": http_http.get("status"),
        "https_alive": bool(http_https.get("alive")),
        "https_status": http_https.get("status"),
        "final_url": (http_https.get("final_url") if http_https.get("alive") else http_http.get("final_url")),
        "title": _pick_title(),
        "server": _pick_server(),
        "tls_days_to_expire": (http_https.get("tls", {}) or {}).get("days_to_expire") if isinstance(http_https, dict) else None,
        "tags": tags_str,
        "timestamp": r.get("timestamp"),
    }


def write_csv(path: str, records: List[Dict[str, Any]]) -> None:
    flat = [_flatten_for_csv(r) for r in records]
    fieldnames = [
        "domain_input", "subdomain", "a", "aaaa",
        "http_alive", "http_status", "https_alive", "https_status",
        "final_url", "title", "server", "tls_days_to_expire",
        "tags", "timestamp"
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in flat:
            w.writerow(row)
