"""Shared helpers: Shannon entropy, Set-Cookie parsing."""
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from math import log2
from typing import Optional

SESSION_HINTS = ("sess", "sid", "token", "auth", "jwt", "login")


def shannon_entropy(token: str) -> float:
    """Shannon entropy in bits per character (paper, Sec. V-A)."""
    if not token:
        return 0.0
    freq = {c: token.count(c) / len(token) for c in set(token)}
    return -sum(p * log2(p) for p in freq.values())


@dataclass
class Cookie:
    name: str
    value: str
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None
    max_age: Optional[int] = None
    expires: Optional[datetime] = None
    domain: Optional[str] = None
    path: Optional[str] = None

    @property
    def lifetime_seconds(self) -> Optional[float]:
        if self.max_age is not None:
            return float(self.max_age)
        if self.expires is not None:
            return (self.expires - datetime.now(timezone.utc)).total_seconds()
        return None

    @property
    def looks_like_session(self) -> bool:
        n = self.name.lower()
        return any(h in n for h in SESSION_HINTS)


def parse_set_cookie(raw: str) -> Optional[Cookie]:
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    c = Cookie(name=name.strip(), value=value.strip())
    for attr in parts[1:]:
        k, _, v = attr.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "secure":
            c.secure = True
        elif k == "httponly":
            c.httponly = True
        elif k == "samesite":
            c.samesite = v.lower() or "unspecified"
        elif k == "max-age":
            try:
                c.max_age = int(v)
            except ValueError:
                pass
        elif k == "expires":
            try:
                dt = parsedate_to_datetime(v)
                c.expires = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                pass
        elif k == "domain":
            c.domain = v
        elif k == "path":
            c.path = v
    return c
