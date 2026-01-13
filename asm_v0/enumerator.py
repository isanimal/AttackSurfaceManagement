import asyncio
import json
from typing import List, Set, Optional
import aiohttp

from utils import bounded_gather, normalize_host


CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"


async def fetch_crtsh(domain: str, timeout: float, user_agent: str, logger) -> Set[str]:
    url = CRT_URL.format(domain=domain)
    headers = {"User-Agent": user_agent}
    out: Set[str] = set()

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(url, timeout=timeout) as resp:
                if resp.status != 200:
                    logger.warning("crt.sh non-200 status=%s domain=%s", resp.status, domain)
                    return out
                text = await resp.text()
    except Exception as e:
        logger.warning("crt.sh request failed domain=%s error=%s", domain, e)
        return out

    # crt.sh can return invalid JSON when empty; handle gracefully
    try:
        data = json.loads(text)
    except Exception:
        # sometimes crt.sh returns multiple JSON objects without array wrapper; try best-effort
        logger.warning("crt.sh JSON parse failed domain=%s", domain)
        return out

    for row in data if isinstance(data, list) else []:
        name_val = row.get("name_value")
        if not name_val:
            continue
        # name_value can contain multiple lines
        for item in str(name_val).splitlines():
            h = normalize_host(item)
            if h.endswith("." + domain) or h == domain:
                out.add(h)
    return out


async def brute_dns(domain: str, wordlist_path: str, timeout: float, concurrency: int, logger) -> Set[str]:
    # lightweight brute: rely on getaddrinfo resolution later to validate
    words = []
    try:
        words = [w.strip() for w in open(wordlist_path, "r", encoding="utf-8", errors="ignore").read().splitlines()]
        words = [w for w in words if w and not w.startswith("#")]
    except Exception as e:
        logger.warning("Failed reading wordlist=%s error=%s", wordlist_path, e)
        return set()

    candidates = {f"{w}.{domain}" for w in words}
    # No DNS query here; resolution stage will filter. Keep v0 simple.
    logger.info("Brute candidates prepared: %d", len(candidates))
    return candidates


async def enumerate_subdomains(
    domain: str,
    passive_only: bool,
    wordlist_path: Optional[str],
    timeout: float,
    concurrency: int,
    user_agent: str,
    max_subdomains: int,
    logger,
) -> List[str]:
    domain = normalize_host(domain)
    results: Set[str] = set()
    results.add(domain)

    crt = await fetch_crtsh(domain, timeout=timeout, user_agent=user_agent, logger=logger)
    results |= crt

    if (not passive_only) and wordlist_path:
        brute = await brute_dns(domain, wordlist_path, timeout=timeout, concurrency=concurrency, logger=logger)
        results |= brute

    # safety cap
    out = sorted(list(results))
    if len(out) > max_subdomains:
        logger.warning("Subdomain cap exceeded (%d > %d). Truncating.", len(out), max_subdomains)
        out = out[:max_subdomains]
    return out
