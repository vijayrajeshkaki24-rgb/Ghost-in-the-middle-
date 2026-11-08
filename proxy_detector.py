"""Module 3: Proxy Detection Engine (weight 0.25) - seven indicators."""
import re
from urllib.parse import urlparse
from .models import Finding
from .http_probe import Probe, median_over_min
from .tls_info import get_cert_info

M = "proxy"
LOGIN_HOST = re.compile(r"(login|sso|auth|accounts?|signin|adfs|portal|idp)", re.I)


def detect(p: Probe, samples: list, timing_threshold_ms: float = 100.0, check_tls: bool = True) -> list:
    out = []
    h = p.headers

    for fid, hdr, w, title in [("XFF", "x-forwarded-for", 2, "X-Forwarded-For header"),
                               ("VIA", "via", 1, "Via header"),
                               ("FORWARDED", "forwarded", 1, "Forwarded header")]:
        present = hdr in h
        out.append(Finding(fid, M, title, w, present,
            f"{hdr}: {h[hdr]}" if present else f"{hdr} not present.",
            "Investigate the interposed hop; strip/validate proxy headers at the edge."))

    deep = p.redirect_depth > 3
    out.append(Finding("REDIRECT_DEPTH", M, "Redirect-chain depth <= 3", 2, deep,
        f"{p.redirect_depth} redirects followed.",
        "Reduce redirect hops in the authentication flow; unexpected hops can indicate a relay."))

    reflect = [c.name for c in p.cookies if len(c.value) >= 8 and c.value in p.body]
    out.append(Finding("TOKEN_REFLECTION", M, "Token reflected in response body", 3, bool(reflect),
        f"Cookie value(s) appear in body: {', '.join(reflect)}" if reflect else "No token reflection.",
        "Never echo session identifiers into page content, URLs or scripts."))

    host = urlparse(p.final_url).hostname or ""
    anomaly, detail = False, "TLS check skipped (not HTTPS)."
    if check_tls and p.final_url.lower().startswith("https://"):
        info = get_cert_info(host, urlparse(p.final_url).port or 443)
        if info["verified"] is False:
            anomaly, detail = True, f"Certificate failed validation: {info['error']}"
        elif info["issuer"] and "let's encrypt" in info["issuer"].lower() and LOGIN_HOST.search(host):
            anomaly, detail = True, f"Let's Encrypt certificate on identity-style host '{host}'."
        else:
            detail = f"Certificate issuer: {info['issuer']}" if info["issuer"] else "Certificate check inconclusive."
    out.append(Finding("TLS_CERT_ANOMALY", M, "TLS certificate anomaly", 2, anomaly, detail,
        "Use certificates from your organisation's expected CA and monitor CT logs for look-alike domains."))

    dev = median_over_min(samples)
    slow = dev > timing_threshold_ms
    out.append(Finding("TIMING_DEVIATION", M, f"Timing deviation > {int(timing_threshold_ms)} ms", 2, slow,
        f"Median response is {dev:.0f} ms above baseline ({len(samples)} samples)." if samples
        else "No timing samples collected.",
        "Consistent added latency can indicate a relay; compare against a known-good baseline."))
    return out
