"""Module 1: Authentication Security Analyzer (weight 0.35)."""
import re
from .models import Finding
from .http_probe import Probe

M = "authentication"


def _session_cookies(p: Probe):
    sc = [c for c in p.cookies if c.looks_like_session]
    return sc or p.cookies


def analyze(p: Probe) -> list:
    https = p.final_url.lower().startswith("https://")
    out = []

    out.append(Finding("HTTPS_ENFORCED", M, "HTTPS enforcement", 3, not https,
        "Final URL is served over HTTPS." if https else f"Final URL {p.final_url} is not HTTPS.",
        "Redirect all HTTP traffic to HTTPS and serve the login flow only over TLS."))

    hsts = p.headers.get("strict-transport-security", "")
    m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
    max_age = int(m.group(1)) if m else 0
    ok = https and max_age >= 31_536_000
    out.append(Finding("HSTS", M, "HSTS (max-age >= 31536000)", 2, not ok,
        f"HSTS max-age={max_age}" if hsts else "Strict-Transport-Security header missing.",
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."))

    csp = p.headers.get("content-security-policy")
    out.append(Finding("CSP", M, "Content-Security-Policy present", 1, not csp,
        "CSP header present." if csp else "Content-Security-Policy header missing.",
        "Define a restrictive Content-Security-Policy (default-src 'self')."))

    cookies = _session_cookies(p)
    if not cookies:
        na = "No cookies set by the target; cookie checks not applicable."
        for fid, title, w, rem in [
            ("COOKIE_SECURE", "Cookie 'Secure' flag", 4, ""),
            ("COOKIE_HTTPONLY", "Cookie 'HttpOnly' flag", 2, ""),
            ("COOKIE_SAMESITE", "Cookie 'SameSite' attribute", 2, "")]:
            out.append(Finding(fid, M, title, w, False, na, rem))
        return out

    def names(pred):
        return ", ".join(c.name for c in cookies if pred(c))

    miss = names(lambda c: not c.secure)
    out.append(Finding("COOKIE_SECURE", M, "Cookie 'Secure' flag", 4, bool(miss),
        f"Missing on: {miss}" if miss else "All session cookies carry Secure.",
        "Set the Secure attribute so cookies are never sent over plain HTTP."))
    miss = names(lambda c: not c.httponly)
    out.append(Finding("COOKIE_HTTPONLY", M, "Cookie 'HttpOnly' flag", 2, bool(miss),
        f"Missing on: {miss}" if miss else "All session cookies carry HttpOnly.",
        "Set HttpOnly to block JavaScript access to session cookies."))
    miss = names(lambda c: not c.samesite)
    out.append(Finding("COOKIE_SAMESITE", M, "Cookie 'SameSite' attribute", 2, bool(miss),
        f"Missing on: {miss}" if miss else "All session cookies set SameSite.",
        "Set SameSite=Lax (or Strict) on all session cookies."))
    return out
