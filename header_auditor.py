#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
header_auditor.py - Security-Headers-Auditor engine and CLI.

Author: USER-Bi (GitHub: Rg-Red)
Version: 1.0.0

Passive web security header scanner. This file is ONLY the execution
engine - the HTTP client, response parser, grader and terminal visualizer.
Every header definition, regex validator, score weight and fix recommendation
lives in rules.py. Add/retune a header rule there; this file never needs to
change for that.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.box import HEAVY, ROUNDED

import rules

# Windows UTF-8 console fix (box-drawing glyphs, banner art, status icons)
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())

__author__ = "USER-Bi"
__maintainer__ = "Rg-Red"
__version__ = "1.0.0"

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "Security-Headers-Auditor/1.0 (+https://github.com/Rg-Red/Security-Headers-Auditor)"
MAX_REDIRECTS = 10
REPORTS_DIR = Path(__file__).resolve().parent / "reports"

console = Console()


# ---------------------------------------------------------------------------
# SECTION 1: Data model
# ---------------------------------------------------------------------------

@dataclass
class RedirectHop:
    url: str
    status_code: int


@dataclass
class ScanResult:
    target_url: str
    final_url: str
    status_code: int
    redirect_chain: List[RedirectHop]
    headers: Dict[str, str]
    findings: List[Dict[str, Any]] = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    risk_label: str = "CRITICAL"
    risk_style: str = "bold red"
    error: Optional[str] = None
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

# ---------------------------------------------------------------------------
# SECTION 2: Network handler
# ---------------------------------------------------------------------------

def normalize_url(raw: str) -> str:
    """Ensure a scheme is present; default to https://."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    return raw


def fetch(url: str, timeout: int = DEFAULT_TIMEOUT,
          insecure: bool = False) -> ScanResult:
    """GET the URL, follow redirects manually to capture the full chain,
    and audit the headers of the final landing response."""
    target = normalize_url(url)
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    chain: List[RedirectHop] = []
    current = target
    response = None

    try:
        for _ in range(MAX_REDIRECTS + 1):
            response = session.get(
                current, timeout=timeout, allow_redirects=False,
                verify=not insecure,
            )
            chain.append(RedirectHop(url=current, status_code=response.status_code))
            if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    break
                current = requests.compat.urljoin(current, location)
                continue
            break
        else:
            return ScanResult(
                target_url=target, final_url=current, status_code=0,
                redirect_chain=chain, headers={},
                error=f"Exceeded {MAX_REDIRECTS} redirects without resolving",
            )
    except requests.exceptions.SSLError as exc:
        return ScanResult(
            target_url=target, final_url=current, status_code=0,
            redirect_chain=chain, headers={},
            error=f"TLS/SSL error: {exc}",
        )
    except requests.exceptions.ConnectionError as exc:
        return ScanResult(
            target_url=target, final_url=current, status_code=0,
            redirect_chain=chain, headers={},
            error=f"Connection failed: {exc}",
        )
    except requests.exceptions.Timeout:
        return ScanResult(
            target_url=target, final_url=current, status_code=0,
            redirect_chain=chain, headers={},
            error=f"Timed out after {timeout}s",
        )
    except requests.exceptions.RequestException as exc:
        return ScanResult(
            target_url=target, final_url=current, status_code=0,
            redirect_chain=chain, headers={},
            error=f"Request failed: {exc}",
        )

    headers = {k: v for k, v in response.headers.items()}
    return ScanResult(
        target_url=target, final_url=current, status_code=response.status_code,
        redirect_chain=chain, headers=headers,
    )

# ---------------------------------------------------------------------------
# SECTION 3: Auditor (applies rules.py against the fetched headers)
# ---------------------------------------------------------------------------

def _header_lookup(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup (HTTP header names are case-insensitive)."""
    lowered = {k.lower(): v for k, v in headers.items()}
    return lowered.get(name.lower())


def audit_headers(result: ScanResult) -> ScanResult:
    """Run every rule in rules.RULES against the scanned response headers."""
    if result.error:
        result.score = 0
        result.grade = "F"
        result.risk_label, result.risk_style = rules.risk_band_for_score(0)
        return result

    findings: List[Dict[str, Any]] = []
    for rule in rules.RULES:
        raw_value = _header_lookup(result.headers, rule["header"])
        status, detail, evidence = rules.run_validator(rule["validator"], raw_value)
        findings.append({
            "header": rule["header"],
            "category": rule["category"],
            "rule": rule,
            "status": status,
            "detail": detail,
            "evidence": evidence,
            "raw_value": raw_value,
            "fix": rules.get_fix(rule["header"]),
            "severity": rules.STATUS_SEVERITY.get(status, "INFO"),
        })

    result.findings = findings
    result.score = rules.compute_score(findings)
    result.grade = rules.grade_for_score(result.score)
    result.risk_label, result.risk_style = rules.risk_band_for_score(result.score)
    return result

# ---------------------------------------------------------------------------
# SECTION 4: Terminal UI (SOC dark theme via rich)
# ---------------------------------------------------------------------------

BANNER = r"""
 ____                       _ _          _   _                _
/ ___|  ___  ___ _   _ _ __(_) |_ _   _  | | | | ___  __ _  __| | ___ _ __ ___
\___ \ / _ \/ __| | | | '__| | __| | | | | |_| |/ _ \/ _` |/ _` |/ _ \ '__/ __|
 ___) |  __/ (__| |_| | |  | | |_| |_| | |  _  |  __/ (_| | (_| |  __/ |  \__ \
|____/ \___|\___|\__,_|_|  |_|\__|\__, | |_| |_|\___|\__,_|\__,_|\___|_|  |___/
                                   |___/        A U D I T O R
"""


def print_banner() -> None:
    console.print(Text(BANNER, style="bold cyan"))
    console.print(
        Align.center(
            Text("Security-Headers-Auditor", style="bold white")
            + Text("  //  Passive Web Security Header Scanner", style="dim white")
        )
    )
    console.print(
        Align.center(Text("Developed by USER-Bi (Rg-Red)", style="dim cyan"))
    )
    console.print(Align.center(Text("github.com/Rg-Red/Security-Headers-Auditor", style="dim cyan")))
    console.rule(style="cyan")


def print_redirect_chain(result: ScanResult) -> None:
    if len(result.redirect_chain) <= 1:
        return
    table = Table(
        title="Redirect Chain", box=ROUNDED, title_style="bold cyan",
        border_style="bright_black", show_lines=False,
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Status", width=8, justify="center")
    table.add_column("URL", overflow="fold")
    for idx, hop in enumerate(result.redirect_chain, start=1):
        style = "bold green" if hop.status_code < 400 else "bold red"
        table.add_row(str(idx), f"[{style}]{hop.status_code}[/{style}]", hop.url)
    console.print(table)


def print_findings_table(result: ScanResult) -> None:
    table = Table(
        title=f"Header Audit - {result.final_url}", box=HEAVY,
        title_style="bold white", header_style="bold white on grey23",
        border_style="bright_black", show_lines=True, expand=True,
    )
    table.add_column("Status", width=10, justify="center")
    table.add_column("Header", style="bold", width=28, overflow="fold")
    table.add_column("Category", width=18, style="dim")
    table.add_column("Finding", overflow="fold")

    status_rank = {s: i for i, s in enumerate(rules.STATUS_ORDER)}
    ordered = sorted(result.findings, key=lambda f: status_rank.get(f["status"], 99))

    for finding in ordered:
        status = finding["status"]
        style = rules.STATUS_THEME.get(status, "white")
        glyph = rules.STATUS_GLYPH.get(status, "")
        status_cell = Text(f"{glyph} {status}", style=style)
        table.add_row(
            status_cell, finding["header"], finding["category"], finding["detail"],
        )
    console.print(table)


def print_findings_panel(result: ScanResult) -> None:
    actionable = [
        f for f in result.findings
        if f["status"] in (rules.STATUS_FAIL, rules.STATUS_MISSING, rules.STATUS_WARNING)
    ]
    if not actionable:
        console.print(Panel(
            Text("No actionable findings - all scored headers pass.", style="bold green"),
            title="Findings", border_style="green", box=ROUNDED,
        ))
        return

    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    actionable.sort(key=lambda f: severity_rank.get(f["severity"], 9))

    lines: List[Text] = []
    for finding in actionable:
        style = rules.STATUS_THEME.get(finding["status"], "white")
        lines.append(Text(f"[{finding['severity']}] ", style=style) +
                     Text(finding["header"], style="bold") +
                     Text(f" - {finding['detail']}", style="white"))
        lines.append(Text(f"    Fix: {finding['fix']}", style="dim cyan"))

    body = Text("\n").join(lines)
    console.print(Panel(
        body, title=f"Findings ({len(actionable)})",
        border_style="yellow", box=ROUNDED,
    ))


def print_score_panel(result: ScanResult) -> None:
    if result.error:
        console.print(Panel(
            Text(result.error, style="bold red"),
            title="Scan Error", border_style="red", box=ROUNDED,
        ))
        return

    grade_style = rules.GRADE_THEME.get(result.grade, "white")
    summary = Text()
    summary.append(f"Score: {result.score}/100   ", style="bold white")
    summary.append(f"Grade: {result.grade}   ", style=grade_style)
    summary.append(f"Risk: {result.risk_label}", style=result.risk_style)

    console.print(Panel(
        Align.center(summary), title="Security Score", border_style=grade_style,
        box=ROUNDED,
    ))

# ---------------------------------------------------------------------------
# SECTION 5: JSON reporter
# ---------------------------------------------------------------------------

def to_report_dict(result: ScanResult) -> Dict[str, Any]:
    """Serialisable representation of a scan for JSON export."""
    return {
        "tool": "Security-Headers-Auditor",
        "version": __version__,
        "author": "USER-Bi (Rg-Red)",
        "scanned_at": result.scanned_at,
        "target_url": result.target_url,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "error": result.error,
        "redirect_chain": [
            {"url": hop.url, "status_code": hop.status_code}
            for hop in result.redirect_chain
        ],
        "score": result.score,
        "grade": result.grade,
        "risk_label": result.risk_label,
        "findings": [
            {
                "header": f["header"],
                "category": f["category"],
                "status": f["status"],
                "severity": f["severity"],
                "detail": f["detail"],
                "raw_value": f["raw_value"],
                "fix": f["fix"],
            }
            for f in result.findings
        ],
    }


def export_json_report(result: ScanResult, directory: Path = REPORTS_DIR) -> Path:
    """Write the scan result as JSON to reports/ and return the file path."""
    directory.mkdir(parents=True, exist_ok=True)
    host = urlparse(result.final_url or result.target_url).hostname or "unknown"
    safe_host = "".join(c if c.isalnum() or c in ".-" else "_" for c in host)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = directory / f"headers_{safe_host}_{timestamp}.json"
    path.write_text(json.dumps(to_report_dict(result), indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# SECTION 6: CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="header_auditor.py",
        description="Security-Headers-Auditor - passive web security header scanner.",
    )
    parser.add_argument("url", help="Target URL (scheme optional, defaults to https://)")
    parser.add_argument(
        "-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "-k", "--insecure", action="store_true",
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "-o", "--output", action="store_true",
        help="Export a JSON report to reports/",
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="Suppress the ASCII banner (useful for scripted runs)",
    )
    return parser


def run_scan(url: str, timeout: int = DEFAULT_TIMEOUT, insecure: bool = False) -> ScanResult:
    """Fetch the target and run the full header audit. Used by CLI and tests."""
    result = fetch(url, timeout=timeout, insecure=insecure)
    return audit_headers(result)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.no_banner:
        print_banner()

    with console.status(f"[bold cyan]Scanning {args.url} ...", spinner="dots"):
        result = run_scan(args.url, timeout=args.timeout, insecure=args.insecure)

    if result.error:
        print_score_panel(result)
        return 1

    print_redirect_chain(result)
    print_findings_table(result)
    print_findings_panel(result)
    print_score_panel(result)

    if args.output:
        path = export_json_report(result)
        console.print(f"\n[dim cyan]JSON report written to[/dim cyan] {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
