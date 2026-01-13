import asyncio
import logging
from datetime import datetime, timezone
from typing import Callable, Awaitable, Any, List


def setup_logger(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("asm_v0")
    if logger.handlers:
        return logger
    lvl = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(lvl)
    h = logging.StreamHandler()
    fmt = logging.Formatter("[%(levelname)s] %(message)s")
    h.setFormatter(fmt)
    logger.addHandler(h)
    return logger


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    # basic sanity remove wildcard prefix
    if host.startswith("*."):
        host = host[2:]
    return host


async def bounded_gather(tasks: List[Callable[[], Awaitable[Any]]], concurrency: int = 100) -> List[Any]:
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _run(fn: Callable[[], Awaitable[Any]]):
        async with sem:
            return await fn()

    coros = [_run(fn) for fn in tasks]
    return await asyncio.gather(*coros, return_exceptions=False)
