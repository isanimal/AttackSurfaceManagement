from typing import Dict, Any, List, Optional


SUSPICIOUS_TITLE_KEYWORDS = [
    "index of /",
    "phpmyadmin",
    "jenkins",
    "grafana",
    "kibana",
    "prometheus",
    "swagger ui",
    "api documentation",
]

ADMIN_PATHS = ["/admin", "/dashboard", "/login", "/phpmyadmin", "/jenkins"]


def _get_http_obj(rec: Dict[str, Any], scheme: str) -> Dict[str, Any]:
    return rec.get("http", {}).get(scheme, {}) if rec.get("http") else {}


def apply_rules(records: List[Dict[str, Any]], logger=None) -> List[Dict[str, Any]]:
    out = []
    for r in records:
        tags: List[str] = []
        http = _get_http_obj(r, "http")
        https = _get_http_obj(r, "https")

        http_alive = bool(http.get("alive"))
        https_alive = bool(https.get("alive"))

        if http_alive and not https_alive:
            tags.append("no-https")

        # redirect chain
        for scheme, obj in [("http", http), ("https", https)]:
            if obj.get("alive") and isinstance(obj.get("redirects"), int) and obj["redirects"] > 3:
                tags.append("open-redirect-chain")
                break

        # tls expiring soon
        tls = https.get("tls", {}) if isinstance(https, dict) else {}
        days = None
        if isinstance(tls, dict):
            days = tls.get("days_to_expire")
        if isinstance(days, int) and days < 14:
            tags.append("tls-expiring-soon")

        # suspicious title
        title = None
        if https_alive:
            title = https.get("title")
        elif http_alive:
            title = http.get("title")

        if isinstance(title, str):
            t = title.strip().lower()
            for kw in SUSPICIOUS_TITLE_KEYWORDS:
                if kw in t:
                    tags.append("suspicious-title")
                    break

        # exposed admin hint (very light, only by title/URL heuristics)
        # v0: if final_url includes common admin paths OR title suggests admin
        final_url = None
        if https_alive:
            final_url = https.get("final_url")
        elif http_alive:
            final_url = http.get("final_url")

        if isinstance(final_url, str):
            fu = final_url.lower()
            if any(p in fu for p in ADMIN_PATHS):
                tags.append("exposed-admin")

        r["tags"] = sorted(list(set(tags)))
        out.append(r)
    return out
