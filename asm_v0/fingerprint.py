import asyncio
import re
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(html: str) -> Optional[str]:
    if not html:
        return None
    m = TITLE_RE.search(html)
    if not m:
        return None
    title = m.group(1)
    title = re.sub(r"\s+", " ", title).strip()
    return title[:200] if title else None


async def tls_days_to_expire(host: str, timeout: float = 10.0) -> Optional[int]:
    # run blocking TLS handshake in a thread
    def _worker() -> Optional[int]:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # Example format: 'Jun  1 12:00:00 2026 GMT'
                not_after = cert.get("notAfter")
                if not not_after:
                    return None
                dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                dt = dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                delta = dt - now
                return int(delta.total_seconds() // 86400)

    return await asyncio.to_thread(_worker)
