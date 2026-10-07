#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rules.py - Audit database for Security-Headers-Auditor.

Author: USER-Bi (GitHub: Rg-Red)
Version: 1.0.0

THIS FILE IS THE SINGLE SOURCE OF TRUTH FOR THE AUDIT.

Everything the scanner knows about HTTP security headers lives here:

  * which headers are audited (``RULES``)
  * how each value is inspected, including regex validators (``validate_*``)
  * how much each header contributes to the score (``weight``)
  * the severity of each finding (``SEVERITY_WEIGHTS``)
  * the remediation text handed back to the operator (``fix``)
  * the deterministic 0-100 score and A+ .. F letter grade

``header_auditor.py`` contains no header knowledge at all - it is only an
engine (HTTP client, parser, grader, reporter, terminal visualizer).
Adding, removing or re-tuning a header rule therefore only requires editing
this file; the engine picks the change up automatically.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

__author__ = "USER-Bi"
__maintainer__ = "Rg-Red"
__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# SECTION 1: Status vocabulary, colours and severities
# ---------------------------------------------------------------------------

STATUS_PASS = "PASS"
STATUS_WARNING = "WARNING"
STATUS_FAIL = "FAIL"
STATUS_MISSING = "MISSING"
STATUS_INFO = "INFO"

STATUS_ORDER = [STATUS_PASS, STATUS_WARNING, STATUS_FAIL, STATUS_MISSING, STATUS_INFO]

# Rich style per status. SOC dark-theme palette.
STATUS_THEME: Dict[str, str] = {
    STATUS_PASS: "bold green",
    STATUS_WARNING: "bold yellow",
    STATUS_FAIL: "bold red",
    STATUS_MISSING: "bold red",
    STATUS_INFO: "bold cyan",
}

STATUS_GLYPH: Dict[str, str] = {
    STATUS_PASS: "[+]",
    STATUS_WARNING: "[!]",
    STATUS_FAIL: "[-]",
    STATUS_MISSING: "[-]",
    STATUS_INFO: "[i]",
}

# How heavy a finding reads to an analyst, independent of its score weight.
SEVERITY_WEIGHTS: Dict[str, str] = {
    "HIGH": "Immediate exploitation surface or complete control loss",
    "MEDIUM": "Weakens defence-in-depth, exploitable in chains",
    "LOW": "Hardening gap or information disclosure",
    "INFO": "Context only, no direct risk",
}

# Status -> severity used for the findings panel.
STATUS_SEVERITY: Dict[str, str] = {
    STATUS_FAIL: "HIGH",
    STATUS_MISSING: "HIGH",
    STATUS_WARNING: "MEDIUM",
    STATUS_PASS: "INFO",
    STATUS_INFO: "INFO",
}

# ---------------------------------------------------------------------------
# SECTION 2: Scoring matrix
# ---------------------------------------------------------------------------

# Scored rules must total 100 so the raw score maps straight to a percentage.
SCORE_STATUS_MULTIPLIER: Dict[str, float] = {
    STATUS_PASS: 1.0,
    STATUS_WARNING: 0.5,
    STATUS_FAIL: 0.0,
    STATUS_MISSING: 0.0,
    STATUS_INFO: 1.0,  # unscored, kept for completeness
}

# Letter grade floor values, checked top-down.
GRADE_THRESHOLDS: List[Tuple[int, str]] = [
    (97, "A+"), (93, "A"), (90, "A-"),
    (87, "B+"), (83, "B"), (80, "B-"),
    (77, "C+"), (73, "C"), (70, "C-"),
    (60, "D"), (0, "F"),
]

GRADE_THEME: Dict[str, str] = {
    "A+": "bold green", "A": "bold green", "A-": "bold green",
    "B+": "bold cyan", "B": "bold cyan", "B-": "bold cyan",
    "C+": "bold yellow", "C": "bold yellow", "C-": "bold yellow",
    "D": "bold red", "F": "bold red",
}

RISK_BANDS: List[Tuple[int, str, str]] = [
    (90, "HARDENED", "bold green"),
    (75, "ACCEPTABLE", "bold cyan"),
    (60, "WEAK", "bold yellow"),
    (0, "CRITICAL", "bold red"),
]

# ---------------------------------------------------------------------------
# SECTION 3: Regex validators
# ---------------------------------------------------------------------------

RE_HEADER_TOKEN = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_|~]+$")
RE_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)\"?", re.IGNORECASE)
RE_DIRECTIVE = re.compile(r"(?P<name>[A-Za-z0-9-]+)(?:\s+(?P<value>[^;]+))?")
RE_IFRAME = re.compile(r"^(DENY|SAMEORIGIN|ALLOW-FROM\s+\S+)$", re.IGNORECASE)
RE_HOST = re.compile(r"^[a-z0-9.-]+(:[0-9]+)?$", re.IGNORECASE)

# Minimum HSTS max-age accepted as strong (180 days) / ideal (1 year).
HSTS_MIN_MAX_AGE = 15552000
HSTS_STRONG_MAX_AGE = 31536000

CSP_UNSAFE_TOKENS = ("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:")
CSP_FALLBACK_ORDER = ("script-src", "default-src")

REFERRER_ALLOWED = (
    "no-referrer", "no-referrer-when-downgrade", "origin",
    "origin-when-cross-origin", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin",
)
REFERRER_WEAK = ("unsafe-url",)
REFERRER_STRONG = (
    "no-referrer", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin",
)

COOP_ALLOWED = ("same-origin", "same-origin-allow-popups", "unsafe-none")
CORP_ALLOWED = ("same-origin", "same-site", "cross-origin")
COEP_ALLOWED = ("require-corp", "credentialless", "unsafe-none")


def parse_csp(policy: str) -> Dict[str, List[str]]:
    """Parse a Content-Security-Policy string into directive -> tokens."""
    directives: Dict[str, List[str]] = {}
    for chunk in policy.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        name = parts[0].lower()
        directives[name] = [p.lower() for p in parts[1:]]
    return directives


def csp_effective(directives: Dict[str, List[str]], name: str) -> Optional[List[str]]:
    """Return directive tokens, falling back to default-src as browsers do."""
    if name in directives:
        return directives[name]
    if "default-src" in directives:
        return directives["default-src"]
    return None


def parse_max_age(value: str) -> Optional[int]:
    """Extract max-age seconds from an HSTS value, or None when absent."""
    match = RE_MAX_AGE.search(value or "")
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None

# ---------------------------------------------------------------------------
# SECTION 4: Per-header deep validators
#
# Every validator returns (status, detail, evidence).
#   status   - one of the STATUS_* constants
#   detail   - one-line human explanation shown in the table
#   evidence - the raw value fragment that triggered the verdict
# ---------------------------------------------------------------------------

def validate_hsts(value: str) -> Tuple[str, str, str]:
    """Strict-Transport-Security: max-age strength + includeSubDomains."""
    if not value:
        return (STATUS_MISSING, "Header absent - TLS downgrade and cookie hijack exposed",
                "no Strict-Transport-Security header")

    max_age = parse_max_age(value)
    lowered = value.lower()
    subs = "includesubdomains" in lowered

    if max_age is None:
        return (STATUS_FAIL, "max-age directive missing - browser ignores the policy", value)
    if max_age == 0:
        return (STATUS_FAIL, "max-age=0 actively disables HSTS", value)
    if max_age < HSTS_MIN_MAX_AGE:
        days = max_age / 86400
        return (STATUS_FAIL,
                f"max-age={max_age}s (~{days:.0f}d) below the 180d floor", value)
    if max_age < HSTS_STRONG_MAX_AGE:
        detail = f"max-age={max_age}s valid but below the 1-year ideal"
        return (STATUS_WARNING, detail + ("" if subs else "; includeSubDomains absent"), value)
    if not subs:
        return (STATUS_WARNING, "1-year max-age set but includeSubDomains absent - "
                                "subdomains stay downgradeable", value)
    if "preload" in lowered:
        return (STATUS_PASS, f"max-age={max_age}s, includeSubDomains, preload", value)
    return (STATUS_PASS, f"max-age={max_age}s with includeSubDomains", value)


def validate_csp(value: str) -> Tuple[str, str, str]:
    """Content-Security-Policy: fallback coverage + unsafe token inspection."""
    if not value:
        return (STATUS_MISSING, "Header absent - no XSS/content injection containment",
                "no Content-Security-Policy header")

    directives = parse_csp(value)
    if not directives:
        return (STATUS_FAIL, "CSP present but empty or unparseable", value)

    problems: List[str] = []
    for token in CSP_UNSAFE_TOKENS:
        for directive in ("script-src", "default-src"):
            if token in directives.get(directive, []):
                problems.append(f"{token} in {directive}")

    has_script = "script-src" in directives
    has_default = "default-src" in directives
    if not has_script and not has_default:
        return (STATUS_FAIL, "No script-src and no default-src - script execution "
                             "is unrestricted", value)
    if not has_script:
        problems.append("script-src absent, inheriting default-src")

    if problems:
        return (STATUS_FAIL, "Unsafe directives: " + ", ".join(problems[:3]), value)

    if "default-src" not in directives:
        return (STATUS_WARNING,
                "script-src hardened but no default-src fallback for other types", value)
    return (STATUS_PASS, "default-src fallback present with no unsafe-inline/unsafe-eval "
                         "or wildcard sources", value)


def validate_x_frame_options(value: str) -> Tuple[str, str, str]:
    """X-Frame-Options: DENY / SAMEORIGIN framing control."""
    if not value:
        return (STATUS_MISSING, "Header absent - clickjacking possible unless CSP "
                                "frame-ancestors is set", "no X-Frame-Options header")

    stripped = value.strip()
    if not RE_IFRAME.match(stripped):
        return (STATUS_FAIL, f"Invalid or deprecated directive {stripped!r}", value)

    upper = stripped.upper()
    if upper == "DENY":
        return (STATUS_PASS, "DENY - no framing permitted", value)
    if upper == "SAMEORIGIN":
        return (STATUS_PASS, "SAMEORIGIN - same-origin framing only", value)
    if upper.startswith("ALLOW-FROM"):
        return (STATUS_WARNING, "ALLOW-FROM is obsolete and ignored by modern browsers",
                value)
    return (STATUS_WARNING, f"Unrecognised directive {stripped!r}", value)


def validate_x_content_type_options(value: str) -> Tuple[str, str, str]:
    """X-Content-Type-Options: nosniff MIME-confusion control."""
    if not value:
        return (STATUS_MISSING, "Header absent - MIME sniffing can turn uploads "
                                "into script", "no X-Content-Type-Options header")
    if value.strip().lower() == "nosniff":
        return (STATUS_PASS, "nosniff - MIME sniffing disabled", value)
    return (STATUS_FAIL, f"Value {value.strip()!r} is not nosniff - browsers ignore it",
            value)


def validate_referrer_policy(value: str) -> Tuple[str, str, str]:
    """Referrer-Policy: URL leakage control across origins."""
    if not value:
        return (STATUS_MISSING, "Header absent - full URLs leak to third parties "
                                "and cross-origin", "no Referrer-Policy header")

    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    effective = tokens[-1] if tokens else ""

    if effective in REFERRER_WEAK:
        return (STATUS_FAIL, "unsafe-url leaks full URLs even to plaintext HTTP", value)
    if effective in REFERRER_STRONG:
        return (STATUS_PASS, f"{effective} - hardened referrer handling", value)
    if effective in REFERRER_ALLOWED:
        return (STATUS_WARNING, f"{effective} works but is weaker than "
                                "strict-origin-when-cross-origin", value)
    return (STATUS_FAIL, f"Unrecognised policy {effective!r}", value)


def validate_permissions_policy(value: str) -> Tuple[str, str, str]:
    """Permissions-Policy: feature gating for powerful browser APIs."""
    if not value:
        return (STATUS_MISSING, "Header absent - camera, mic, geolocation and "
                                "friends are not gated", "no Permissions-Policy header")

    directives = [d.strip() for d in value.split(",") if d.strip()]
    if not directives:
        return (STATUS_FAIL, "Header present but no directives declared", value)

    wildcard: List[str] = []
    for directive in directives:
        body = directive.split("=", 1)
        if len(body) == 2 and "*" in body[1]:
            wildcard.append(body[0].strip())

    if wildcard:
        return (STATUS_WARNING,
                "Wildcard grant for: " + ", ".join(wildcard[:3]), value)
    return (STATUS_PASS, f"{len(directives)} feature directives declared", value)


def validate_header_token(value: str) -> Tuple[str, str, str]:
    """Generic validator: header must be present and well-formed (X-XSS-Protection)."""
    if not value:
        return (STATUS_MISSING, "Header absent", "no header value")
    if not RE_HEADER_TOKEN.match(value.strip().split(";")[0].strip()):
        return (STATUS_FAIL, f"Malformed value {value!r}", value)
    if value.strip().lower().startswith("0"):
        return (STATUS_INFO, "Modern best practice is to disable the legacy "
                             "XSS auditor (value 0)", value)
    return (STATUS_PASS, "Header present and well-formed", value)


def _make_flag_validator(allowed: Tuple[str, ...]):
    """Build a validator that requires membership in a fixed value set."""
    def _validator(value: str) -> Tuple[str, str, str]:
        if not value:
            return (STATUS_MISSING, "Header absent", "no header value")
        token = value.strip().lower().split(";")[0].strip()
        if token in allowed:
            return (STATUS_PASS, f"{token} accepted", value)
        if "*" in token or "null" in token:
            return (STATUS_WARNING, f"Overly permissive value {token!r}", value)
        return (STATUS_WARNING, f"{token!r} is not in the recommended set "
                                f"({', '.join(allowed)})", value)
    return _validator


def validate_advisory(value: str) -> Tuple[str, str, str]:
    """Informational headers never influence the score."""
    if not value:
        return (STATUS_INFO, "Not advertised (optional)", "no header value")
    return (STATUS_INFO, f"Advertised: {value[:60]}", value)


VALIDATORS = {
    "hsts": validate_hsts,
    "csp": validate_csp,
    "x_frame_options": validate_x_frame_options,
    "x_content_type_options": validate_x_content_type_options,
    "referrer_policy": validate_referrer_policy,
    "permissions_policy": validate_permissions_policy,
    "header_token": validate_header_token,
    "advisory": validate_advisory,
    "coop": _make_flag_validator(COOP_ALLOWED),
    "corp": _make_flag_validator(CORP_ALLOWED),
    "coep": _make_flag_validator(COEP_ALLOWED),
}

# ---------------------------------------------------------------------------
# SECTION 5: Remediation snippets
# ---------------------------------------------------------------------------

FIXES: Dict[str, str] = {
    "Strict-Transport-Security": (
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains; "
        "preload' once every response is served over HTTPS."
    ),
    "Content-Security-Policy": (
        "Define default-src 'self' plus an explicit script-src without "
        "'unsafe-inline'/'unsafe-eval'; use nonces or hashes for inline scripts."
    ),
    "X-Frame-Options": (
        "Send 'X-Frame-Options: DENY' (or SAMEORIGIN if framing is required) "
        "and mirror it with CSP frame-ancestors."
    ),
    "X-Content-Type-Options": (
        "Send 'X-Content-Type-Options: nosniff' on every response, including "
        "error pages and static assets."
    ),
    "Referrer-Policy": (
        "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or "
        "no-referrer for maximum privacy)."
    ),
    "Permissions-Policy": (
        "Send 'Permissions-Policy: camera=(), microphone=(), geolocation=(), "
        "interest-cohort=()' and explicitly allow-list only the APIs you use."
    ),
    "X-XSS-Protection": (
        "Modern browsers removed the XSS auditor; send "
        "'X-XSS-Protection: 0' to avoid legacy filter-based XSS side channels."
    ),
    "Cross-Origin-Opener-Policy": (
        "Send 'Cross-Origin-Opener-Policy: same-origin' to isolate the "
        "browsing context from cross-origin popups/tabs."
    ),
    "Cross-Origin-Resource-Policy": (
        "Send 'Cross-Origin-Resource-Policy: same-origin' (or same-site) to "
        "stop other origins from embedding your responses."
    ),
    "Cross-Origin-Embedder-Policy": (
        "Send 'Cross-Origin-Embedder-Policy: require-corp' to enable full "
        "cross-origin isolation alongside COOP."
    ),
    "Server": (
        "Suppress or generalise the Server header (e.g. via reverse proxy) "
        "to avoid advertising exact software/version."
    ),
    "X-Powered-By": (
        "Disable or strip the X-Powered-By header at the framework/proxy "
        "level to reduce fingerprinting surface."
    ),
}

DEFAULT_FIX = "Review the header specification and align the value with current OWASP guidance."


# ---------------------------------------------------------------------------
# SECTION 6: The rule table
#
# weight   - points lost (as a share of 100) when the header fully fails;
#            scored headers must sum to 100.
# scored   - False for INFO-only headers that never move the score.
# ---------------------------------------------------------------------------

RULES: List[Dict[str, Any]] = [
    {
        "header": "Strict-Transport-Security",
        "key": "hsts",
        "validator": "hsts",
        "weight": 20,
        "scored": True,
        "category": "Transport",
    },
    {
        "header": "Content-Security-Policy",
        "key": "csp",
        "validator": "csp",
        "weight": 25,
        "scored": True,
        "category": "Content Injection",
    },
    {
        "header": "X-Frame-Options",
        "key": "x_frame_options",
        "validator": "x_frame_options",
        "weight": 15,
        "scored": True,
        "category": "Clickjacking",
    },
    {
        "header": "X-Content-Type-Options",
        "key": "x_content_type_options",
        "validator": "x_content_type_options",
        "weight": 10,
        "scored": True,
        "category": "MIME Sniffing",
    },
    {
        "header": "Referrer-Policy",
        "key": "referrer_policy",
        "validator": "referrer_policy",
        "weight": 10,
        "scored": True,
        "category": "Information Leakage",
    },
    {
        "header": "Permissions-Policy",
        "key": "permissions_policy",
        "validator": "permissions_policy",
        "weight": 10,
        "scored": True,
        "category": "Feature Policy",
    },
    {
        "header": "Cross-Origin-Opener-Policy",
        "key": "coop",
        "validator": "coop",
        "weight": 5,
        "scored": True,
        "category": "Cross-Origin Isolation",
    },
    {
        "header": "Cross-Origin-Resource-Policy",
        "key": "corp",
        "validator": "corp",
        "weight": 5,
        "scored": True,
        "category": "Cross-Origin Isolation",
    },
    {
        "header": "X-XSS-Protection",
        "key": "x_xss_protection",
        "validator": "header_token",
        "weight": 0,
        "scored": False,
        "category": "Legacy",
    },
    {
        "header": "Cross-Origin-Embedder-Policy",
        "key": "coep",
        "validator": "coep",
        "weight": 0,
        "scored": False,
        "category": "Cross-Origin Isolation",
    },
    {
        "header": "Server",
        "key": "server",
        "validator": "advisory",
        "weight": 0,
        "scored": False,
        "category": "Fingerprinting",
    },
    {
        "header": "X-Powered-By",
        "key": "x_powered_by",
        "validator": "advisory",
        "weight": 0,
        "scored": False,
        "category": "Fingerprinting",
    },
]

SCORED_WEIGHT_TOTAL = sum(rule["weight"] for rule in RULES if rule["scored"])


def get_fix(header: str) -> str:
    """Remediation text for a given header name."""
    return FIXES.get(header, DEFAULT_FIX)


def run_validator(validator_name: str, value: Optional[str]) -> Tuple[str, str, str]:
    """Dispatch a header value to its named validator."""
    func = VALIDATORS[validator_name]
    return func(value or "")


def grade_for_score(score: int) -> str:
    """Map a 0-100 score to a letter grade."""
    for floor, grade in GRADE_THRESHOLDS:
        if score >= floor:
            return grade
    return "F"


def risk_band_for_score(score: int) -> Tuple[str, str]:
    """Map a 0-100 score to a (label, style) risk band."""
    for floor, label, style in RISK_BANDS:
        if score >= floor:
            return label, style
    return "CRITICAL", "bold red"


def compute_score(findings: List[Dict[str, Any]]) -> int:
    """Deterministic 0-100 score from a list of per-header finding dicts."""
    if SCORED_WEIGHT_TOTAL == 0:
        return 0
    earned = 0.0
    for finding in findings:
        rule = finding["rule"]
        if not rule["scored"]:
            continue
        multiplier = SCORE_STATUS_MULTIPLIER.get(finding["status"], 0.0)
        earned += rule["weight"] * multiplier
    return round((earned / SCORED_WEIGHT_TOTAL) * 100)