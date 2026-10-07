#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_headers.py - Offline unit tests for Security-Headers-Auditor.

Author: USER-Bi (GitHub: Rg-Red)

No network access required: requests.Session.get is monkeypatched with a
fake response factory so every scenario is fully deterministic.

Run with:
    python -m unittest test_headers.py -v
or simply:
    python test_headers.py
"""

from __future__ import annotations

import unittest
from unittest.mock import patch
from typing import Dict, List, Optional, Tuple

import requests

import header_auditor as engine
import rules


# ---------------------------------------------------------------------------
# Fake HTTP layer
# ---------------------------------------------------------------------------

class FakeResponse:
    """Minimal stand-in for requests.Response used by fetch()."""

    def __init__(self, status_code: int, headers: Dict[str, str]):
        self.status_code = status_code
        self.headers = headers
        self.is_redirect = status_code in (301, 302, 303, 307, 308)


def make_fake_get(script: List[Tuple[int, Dict[str, str]]]):
    """Build a fake Session.get that replays a scripted sequence of hops.

    ``script`` is a list of (status_code, headers) tuples consumed in order
    as fetch() follows redirects; the last entry is the landing page.
    """
    calls = {"i": 0}

    def _fake_get(self, url, timeout=None, allow_redirects=False, verify=True):
        idx = min(calls["i"], len(script) - 1)
        status_code, headers = script[idx]
        calls["i"] += 1
        return FakeResponse(status_code, headers)

    return _fake_get


def scan_with_headers(headers: Dict[str, str], final_status: int = 200) -> engine.ScanResult:
    """Run the full engine against a single-hop fake response."""
    script = [(final_status, headers)]
    with patch.object(requests.Session, "get", make_fake_get(script)):
        result = engine.fetch("https://example.test")
    return engine.audit_headers(result)


def scan_with_redirects(hops: List[Tuple[int, Dict[str, str]]]) -> engine.ScanResult:
    """Run the full engine against a scripted multi-hop redirect chain."""
    with patch.object(requests.Session, "get", make_fake_get(hops)):
        result = engine.fetch("https://example.test")
    return engine.audit_headers(result)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "X-XSS-Protection": "0",
}

WEAK_HSTS_HEADERS = dict(SECURE_HEADERS)
WEAK_HSTS_HEADERS["Strict-Transport-Security"] = "max-age=600"

UNSAFE_CSP_HEADERS = dict(SECURE_HEADERS)
UNSAFE_CSP_HEADERS["Content-Security-Policy"] = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'"
)

# ---------------------------------------------------------------------------
# Tests: fully secure header set
# ---------------------------------------------------------------------------

class TestSecureHeaderSet(unittest.TestCase):
    """A hardened response should score high and raise no HIGH findings."""

    @classmethod
    def setUpClass(cls):
        cls.result = scan_with_headers(SECURE_HEADERS)

    def test_no_error(self):
        self.assertIsNone(self.result.error)

    def test_score_is_high(self):
        self.assertGreaterEqual(self.result.score, 90)

    def test_grade_is_top_tier(self):
        self.assertIn(self.result.grade, ("A+", "A", "A-"))

    def test_no_missing_or_fail_among_scored_headers(self):
        bad = [
            f for f in self.result.findings
            if f["rule"]["scored"] and f["status"] in (rules.STATUS_FAIL, rules.STATUS_MISSING)
        ]
        self.assertEqual(bad, [], msg=f"Unexpected failures: {bad}")

    def test_hsts_passes(self):
        finding = self._find("Strict-Transport-Security")
        self.assertEqual(finding["status"], rules.STATUS_PASS)

    def test_csp_passes(self):
        finding = self._find("Content-Security-Policy")
        self.assertEqual(finding["status"], rules.STATUS_PASS)

    def _find(self, header: str) -> Dict:
        return next(f for f in self.result.findings if f["header"] == header)


# ---------------------------------------------------------------------------
# Tests: weak HSTS (short max-age)
# ---------------------------------------------------------------------------

class TestWeakHSTS(unittest.TestCase):
    """A short max-age must be penalised even though HSTS is present."""

    @classmethod
    def setUpClass(cls):
        cls.result = scan_with_headers(WEAK_HSTS_HEADERS)

    def test_hsts_is_not_passing(self):
        finding = next(f for f in self.result.findings
                        if f["header"] == "Strict-Transport-Security")
        self.assertIn(finding["status"], (rules.STATUS_FAIL, rules.STATUS_WARNING))

    def test_score_lower_than_fully_secure(self):
        secure_score = scan_with_headers(SECURE_HEADERS).score
        self.assertLess(self.result.score, secure_score)

    def test_validator_reports_short_duration(self):
        status, detail, _ = rules.validate_hsts("max-age=600")
        self.assertEqual(status, rules.STATUS_FAIL)
        self.assertIn("180d", detail)


# ---------------------------------------------------------------------------
# Tests: unsafe CSP (unsafe-inline / unsafe-eval)
# ---------------------------------------------------------------------------

class TestUnsafeCSP(unittest.TestCase):
    """unsafe-inline/unsafe-eval in script-src must fail the CSP check."""

    @classmethod
    def setUpClass(cls):
        cls.result = scan_with_headers(UNSAFE_CSP_HEADERS)

    def test_csp_fails(self):
        finding = next(f for f in self.result.findings
                        if f["header"] == "Content-Security-Policy")
        self.assertEqual(finding["status"], rules.STATUS_FAIL)
        self.assertIn("unsafe-inline", finding["detail"])

    def test_score_lower_than_fully_secure(self):
        secure_score = scan_with_headers(SECURE_HEADERS).score
        self.assertLess(self.result.score, secure_score)

    def test_missing_default_src_also_fails(self):
        status, detail, _ = rules.validate_csp("script-src 'self'")
        self.assertIn(status, (rules.STATUS_PASS, rules.STATUS_WARNING))

    def test_empty_csp_fails(self):
        status, _, _ = rules.validate_csp("")
        self.assertEqual(status, rules.STATUS_MISSING)


# ---------------------------------------------------------------------------
# Tests: missing headers entirely
# ---------------------------------------------------------------------------

class TestMissingHeaders(unittest.TestCase):
    """An empty header set should produce MISSING findings and a floor score."""

    @classmethod
    def setUpClass(cls):
        cls.result = scan_with_headers({})

    def test_all_scored_headers_missing_or_failed(self):
        for finding in self.result.findings:
            if finding["rule"]["scored"]:
                self.assertIn(finding["status"], (rules.STATUS_MISSING, rules.STATUS_FAIL))

    def test_score_is_zero(self):
        self.assertEqual(self.result.score, 0)

    def test_grade_is_f(self):
        self.assertEqual(self.result.grade, "F")

    def test_risk_band_is_critical(self):
        self.assertEqual(self.result.risk_label, "CRITICAL")

    def test_findings_panel_has_high_severity_items(self):
        highs = [f for f in self.result.findings if f["severity"] == "HIGH"]
        self.assertTrue(len(highs) > 0)


# ---------------------------------------------------------------------------
# Tests: redirect chain simulation
# ---------------------------------------------------------------------------

class TestRedirectChain(unittest.TestCase):
    """fetch() must follow redirects and audit only the final landing page."""

    @classmethod
    def setUpClass(cls):
        cls.hops = [
            (301, {"Location": "https://example.test/step2"}),
            (302, {"Location": "https://example.test/final"}),
            (200, SECURE_HEADERS),
        ]
        cls.result = scan_with_redirects(cls.hops)

    def test_chain_length_matches_hops(self):
        self.assertEqual(len(self.result.redirect_chain), 3)

    def test_chain_statuses_in_order(self):
        statuses = [hop.status_code for hop in self.result.redirect_chain]
        self.assertEqual(statuses, [301, 302, 200])

    def test_final_status_is_landing_page(self):
        self.assertEqual(self.result.status_code, 200)

    def test_audit_runs_against_final_headers(self):
        self.assertGreaterEqual(self.result.score, 90)

    def test_redirect_loop_without_location_breaks(self):
        hops = [(301, {}), (200, SECURE_HEADERS)]
        result = scan_with_redirects(hops)
        self.assertEqual(len(result.redirect_chain), 1)
        self.assertEqual(result.status_code, 301)


# ---------------------------------------------------------------------------
# Tests: individual validators (regex / deep-inspection unit coverage)
# ---------------------------------------------------------------------------

class TestValidators(unittest.TestCase):

    def test_hsts_zero_max_age_fails(self):
        status, _, _ = rules.validate_hsts("max-age=0")
        self.assertEqual(status, rules.STATUS_FAIL)

    def test_hsts_missing_subdomains_warns(self):
        status, _, _ = rules.validate_hsts("max-age=31536000")
        self.assertEqual(status, rules.STATUS_WARNING)

    def test_x_frame_options_allow_from_warns(self):
        status, _, _ = rules.validate_x_frame_options("ALLOW-FROM https://a.test")
        self.assertEqual(status, rules.STATUS_WARNING)

    def test_x_content_type_options_wrong_value_fails(self):
        status, _, _ = rules.validate_x_content_type_options("sniff")
        self.assertEqual(status, rules.STATUS_FAIL)

    def test_referrer_policy_unsafe_url_fails(self):
        status, _, _ = rules.validate_referrer_policy("unsafe-url")
        self.assertEqual(status, rules.STATUS_FAIL)

    def test_permissions_policy_wildcard_warns(self):
        status, _, _ = rules.validate_permissions_policy("geolocation=*")
        self.assertEqual(status, rules.STATUS_WARNING)

    def test_grade_thresholds_monotonic(self):
        self.assertEqual(rules.grade_for_score(100), "A+")
        self.assertEqual(rules.grade_for_score(0), "F")
        self.assertEqual(rules.grade_for_score(65), "D")

    def test_compute_score_perfect_set(self):
        result = scan_with_headers(SECURE_HEADERS)
        self.assertEqual(result.score, rules.compute_score(result.findings))


if __name__ == "__main__":
    unittest.main(verbosity=2)