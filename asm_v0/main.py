import argparse
import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any

from enumerator import enumerate_subdomains
from resolver import resolve_hosts
from probe import probe_http
from rules import apply_rules
from output import write_json, write_csv
from utils import utc_now_iso, setup_logger


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="ASM v0 - minimal attack surface inventory")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain", help="Single domain, e.g. example.com")
    g.add_argument("--domains", help="File containing domains (one per line)")

    p.add_argument("-o", "--output", required=True, help="Output file path (.json or .csv)")
    p.add_argument("--format", choices=["json", "csv"], default=None, help="Output format override")
    p.add_argument("--concurrency", type=int, default=100, help="Max concurrent tasks (default: 100)")
    p.add_argument("--timeout", type=float, default=10.0, help="Timeout seconds (default: 10)")
    p.add_argument("--passive-only", action="store_true", help="Only passive enum (crt.sh), disable brute")
    p.add_argument("--wordlist", default=None, help="Wordlist for DNS brute (optional)")
    p.add_argument("--max-subdomains", type=int, default=5000, help="Safety cap (default: 5000)")
    p.add_argument("--user-agent", default="asm-v0/1.0", help="HTTP User-Agent")
    p.add_argument("--no-tls", action="store_true", help="Disable TLS expiry check (faster)")
    p.add_argument("--log", default="INFO", help="Log level: DEBUG, INFO, WARNING, ERROR")

    return p.parse_args()


def read_domains_file(path: str) -> List[str]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    out = []
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        out.append(ln)
    return out


async def run_for_domain(domain: str, cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    logger = cfg["logger"]
    logger.info("Domain input: %s", domain)

    subs = await enumerate_subdomains(
        domain=domain,
        passive_only=cfg["passive_only"],
        wordlist_path=cfg["wordlist"],
        timeout=cfg["timeout"],
        concurrency=cfg["concurrency"],
        user_agent=cfg["user_agent"],
        max_subdomains=cfg["max_subdomains"],
        logger=logger,
    )
    logger.info("Enumerated subdomains: %d", len(subs))

    resolved = await resolve_hosts(
        hosts=subs,
        timeout=cfg["timeout"],
        concurrency=cfg["concurrency"],
        logger=logger,
    )
    live_candidates = [h for h in resolved if h.get("dns", {}).get("resolved") is True]
    logger.info("Resolved hosts: %d/%d", len(live_candidates), len(resolved))

    probed = await probe_http(
        host_records=resolved,
        timeout=cfg["timeout"],
        concurrency=cfg["concurrency"],
        user_agent=cfg["user_agent"],
        check_tls=not cfg["no_tls"],
        logger=logger,
    )
    final = apply_rules(probed, logger=logger)

    # attach metadata
    now = utc_now_iso()
    for r in final:
        r["domain_input"] = domain
        r["timestamp"] = now
    return final


async def main_async() -> int:
    args = parse_args()
    logger = setup_logger(args.log)

    fmt = args.format
    if fmt is None:
        out_lower = args.output.lower()
        if out_lower.endswith(".json"):
            fmt = "json"
        elif out_lower.endswith(".csv"):
            fmt = "csv"
        else:
            fmt = "json"

    cfg = {
        "passive_only": args.passive_only,
        "wordlist": args.wordlist,
        "timeout": args.timeout,
        "concurrency": args.concurrency,
        "user_agent": args.user_agent,
        "max_subdomains": args.max_subdomains,
        "no_tls": args.no_tls,
        "logger": logger,
    }

    if args.domain:
        domains = [args.domain.strip()]
    else:
        domains = read_domains_file(args.domains)

    all_records: List[Dict[str, Any]] = []
    for d in domains:
        try:
            recs = await run_for_domain(d, cfg)
            all_records.extend(recs)
        except Exception as e:
            logger.exception("Failed processing domain=%s error=%s", d, e)

    if fmt == "json":
        write_json(args.output, all_records)
        logger.info("Wrote JSON: %s (records=%d)", args.output, len(all_records))
    else:
        write_csv(args.output, all_records)
        logger.info("Wrote CSV: %s (records=%d)", args.output, len(all_records))

    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
