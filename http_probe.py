"""HTTP probing: follows redirects manually so the chain can be measured."""
import statistics
import time
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urljoin

import requests

from .utils import Cookie, parse_set_cookie

UA = "ACASE/1.0 (authorised security assessment)"


@dataclass
class Probe:
    url: str
    final_url: str
    status: int
    headers: dict            # lower-cased header names
    cookies: List[Cookie]
    redirect_depth: int
    body: str
    elapsed_ms: float


def _raw_set_cookies(resp) -> List[str]:
    try:
        return list(resp.raw.headers.getlist("Set-Cookie"))
    except Exception:
        v = resp.headers.get("Set-Cookie")
        return [v] if v else []


def probe(url: str, timeout: int = 10, max_redirects: int = 10, verify: bool = True) -> Probe:
    s = requests.Session()
    s.headers["User-Agent"] = UA
    cookies = {}
    current, hops = url, 0
    start = time.perf_counter()
    while True:
        r = s.get(current, timeout=timeout, allow_redirects=False, verify=verify)
        for raw in _raw_set_cookies(r):
            c = parse_set_cookie(raw)
            if c:
                cookies[c.name] = c
        if r.is_redirect and r.headers.get("Location") and hops < max_redirects:
            current = urljoin(current, r.headers["Location"])
            hops += 1
            continue
        break
    elapsed = (time.perf_counter() - start) * 1000
    return Probe(
        url=url,
        final_url=current,
        status=r.status_code,
        headers={k.lower(): v for k, v in r.headers.items()},
        cookies=list(cookies.values()),
        redirect_depth=hops,
        body=r.text[:200_000],
        elapsed_ms=elapsed,
    )


def timing_samples(url: str, n: int = 5, timeout: int = 10, verify: bool = True) -> List[float]:
    """Independent requests (fresh connections), response time in ms."""
    out = []
    for _ in range(n):
        t = time.perf_counter()
        try:
            requests.get(url, timeout=timeout, verify=verify, headers={"User-Agent": UA})
        except requests.RequestException:
            continue
        out.append((time.perf_counter() - t) * 1000)
    return out


def median_over_min(samples: List[float]) -> float:
    if len(samples) < 2:
        return 0.0
    return statistics.median(samples) - min(samples)
