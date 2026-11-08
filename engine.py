import time
from urllib.parse import urlparse

from . import auth_analyzer, session_validator, proxy_detector, risk
from .http_probe import probe, timing_samples


def validate_target(url: str) -> str:
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("Target must be a valid http(s) URL.")
    return url


def run_scan(url: str, cfg) -> dict:
    validate_target(url)
    t0 = time.perf_counter()
    p1 = probe(url, cfg.SCAN_TIMEOUT_SECONDS, verify=cfg.VERIFY_TLS)
    p2 = probe(url, cfg.SCAN_TIMEOUT_SECONDS, verify=cfg.VERIFY_TLS)  # independent client
    samples = timing_samples(url, cfg.TIMING_SAMPLES, cfg.SCAN_TIMEOUT_SECONDS, cfg.VERIFY_TLS)

    findings = []
    findings += auth_analyzer.analyze(p1)
    findings += session_validator.validate(p1, p2, cfg.ENTROPY_THRESHOLD)
    findings += proxy_detector.detect(p1, samples, cfg.PROXY_TIMING_THRESHOLD_MS)

    summary = risk.compute(findings)
    return {
        "target": url,
        "final_url": p1.final_url,
        "http_status": p1.status,
        "checks_run": len(findings),
        "checks_failed": sum(f.failed for f in findings),
        "scan_seconds": round(time.perf_counter() - t0, 2),
        **summary,
        "findings": [f.to_dict() for f in findings],
    }
