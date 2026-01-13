import asyncio
import time
from typing import Dict, Any, List, Optional
import aiohttp

from fingerprint import extract_title, tls_days_to_expire
from utils import bounded_gather


COMMON_HEADERS = ["server", "x-powered-by"]


async def fetch_url(session: aiohttp.ClientSession, url: str, timeout: float) -> Dict[str, Any]:
    start = time.perf_counter()
    try:
        async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
            rt_ms = int((time.perf_counter() - start) * 1000)
            text = ""
            # Only read limited body to get title; avoid large downloads
            try:
                text = await resp.text(errors="ignore")
                if len(text) > 200_000:
                    text = text[:200_000]
            except Exception:
                text = ""

            headers = {k.lower(): v for k, v in resp.headers.items()}
            out_headers = {h: headers.get(h) for h in COMMON_HEADERS if headers.get(h)}
            title = extract_title(text)

            return {
                "alive": True,
                "status": resp.status,
                "final_url": str(resp.url),
                "rt_ms": rt_ms,
                "redirects": len(resp.history),
                "title": title,
                "headers": out_headers,
            }
    except Exception:
        return {"alive": False}


async def probe_one(host_record: Dict[str, Any], timeout: float, user_agent: str, check_tls: bool, logger) -> Dict[str, Any]:
    host = host_record.get("subdomain")
    out = dict(host_record)
    out["http"] = {"http": {"alive": False}, "https": {"alive": False}}

    headers = {"User-Agent": user_agent}
    connector = aiohttp.TCPConnector(ssl=False)  # manage TLS manually for expiry; aiohttp still can do https
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        # http
        http_url = f"http://{host}"
        http_res = await fetch_url(session, http_url, timeout=timeout)
        out["http"]["http"] = http_res

        # https
        https_url = f"https://{host}"
        https_res = await fetch_url(session, https_url, timeout=timeout)
        if https_res.get("alive") and check_tls:
            try:
                days = await tls_days_to_expire(host, timeout=timeout)
                if days is not None:
                    https_res["tls"] = {"days_to_expire": days}
            except Exception as e:
                logger.debug("TLS check failed host=%s error=%s", host, e)

        out["http"]["https"] = https_res

    return out


async def probe_http(
    host_records: List[Dict[str, Any]],
    timeout: float,
    concurrency: int,
    user_agent: str,
    check_tls: bool,
    logger
) -> List[Dict[str, Any]]:
    tasks = [
        lambda r=r: probe_one(r, timeout=timeout, user_agent=user_agent, check_tls=check_tls, logger=logger)
        for r in host_records
    ]
    return await bounded_gather(tasks, concurrency=concurrency)
