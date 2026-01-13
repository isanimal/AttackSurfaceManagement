import asyncio
import socket
from typing import List, Dict, Any

from utils import bounded_gather


async def resolve_one(host: str, timeout: float, logger) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "subdomain": host,
        "dns": {"resolved": False, "a": [], "aaaa": []},
    }

    try:
        loop = asyncio.get_running_loop()

        async def _ga(family):
            return await loop.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)

        # resolve A/AAAA (best effort)
        a_task = asyncio.wait_for(_ga(socket.AF_INET), timeout=timeout)
        aaaa_task = asyncio.wait_for(_ga(socket.AF_INET6), timeout=timeout)

        a_res = None
        aaaa_res = None
        try:
            a_res = await a_task
        except Exception:
            a_res = None
        try:
            aaaa_res = await aaaa_task
        except Exception:
            aaaa_res = None

        ips_v4 = set()
        ips_v6 = set()
        if a_res:
            for r in a_res:
                ip = r[4][0]
                ips_v4.add(ip)
        if aaaa_res:
            for r in aaaa_res:
                ip = r[4][0]
                ips_v6.add(ip)

        record["dns"]["a"] = sorted(list(ips_v4))
        record["dns"]["aaaa"] = sorted(list(ips_v6))
        record["dns"]["resolved"] = bool(ips_v4 or ips_v6)

    except Exception as e:
        logger.debug("Resolve failed host=%s error=%s", host, e)

    return record


async def resolve_hosts(hosts: List[str], timeout: float, concurrency: int, logger) -> List[Dict[str, Any]]:
    tasks = [lambda h=h: resolve_one(h, timeout=timeout, logger=logger) for h in hosts]
    return await bounded_gather(tasks, concurrency=concurrency)
