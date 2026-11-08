"""Module 2: Session Token Validator (weight 0.40)."""
from .models import Finding
from .http_probe import Probe
from .utils import shannon_entropy

M = "session"
MAX_LIFETIME = 7 * 24 * 3600  # 7 days


def _tokens(p: Probe):
    sc = [c for c in p.cookies if c.looks_like_session]
    return sc or p.cookies


def validate(p1: Probe, p2: Probe, entropy_threshold: float = 3.5) -> list:
    toks = _tokens(p1)
    out = []
    if not toks:
        na = "No session cookies issued; session checks not applicable."
        for fid, title, w in [("TOKEN_LENGTH", "Token length >= 32 chars", 3),
                              ("TOKEN_ENTROPY", "Token Shannon entropy", 5),
                              ("TOKEN_EXPIRATION", "Expiration policy", 3),
                              ("SESSION_REUSE", "Session token reuse", 4),
                              ("SECURE_TRANSMISSION", "Secure transmission", 3)]:
            out.append(Finding(fid, M, title, w, False, na, ""))
        return out

    short = [c.name for c in toks if len(c.value) < 32]
    out.append(Finding("TOKEN_LENGTH", M, "Token length >= 32 chars", 3, bool(short),
        f"Short tokens: {', '.join(short)}" if short else "All tokens >= 32 chars.",
        "Use at least 128 bits of CSPRNG output (32+ hex/base64 chars)."))

    low = [(c.name, round(shannon_entropy(c.value), 2)) for c in toks
           if shannon_entropy(c.value) < entropy_threshold]
    out.append(Finding("TOKEN_ENTROPY", M, f"Token entropy >= {entropy_threshold} bits/char", 5, bool(low),
        "Low entropy: " + ", ".join(f"{n}={e}" for n, e in low) if low else "Entropy meets threshold.",
        "Generate tokens with a cryptographically secure RNG; never derive them from time/user data."))

    long_lived = [c.name for c in toks if (c.lifetime_seconds or 0) > MAX_LIFETIME]
    out.append(Finding("TOKEN_EXPIRATION", M, "Expiration policy (<= 7 days)", 3, bool(long_lived),
        f"Long-lived cookies: {', '.join(long_lived)}" if long_lived else "No excessive lifetime.",
        "Use short idle/absolute session timeouts and rotate tokens at login."))

    v1 = {c.name: c.value for c in toks}
    v2 = {c.name: c.value for c in _tokens(p2)}
    reused = [n for n in v1 if n in v2 and v1[n] == v2[n]]
    out.append(Finding("SESSION_REUSE", M, "Session reuse (static tokens)", 4, bool(reused),
        f"Same value issued to independent clients: {', '.join(reused)}" if reused
        else "Fresh tokens issued per client.",
        "Issue a new random token for every session and regenerate on authentication."))

    insecure = not p1.final_url.lower().startswith("https://") or any(not c.secure for c in toks)
    out.append(Finding("SECURE_TRANSMISSION", M, "Secure transmission of tokens", 3, insecure,
        "Tokens can travel over unencrypted channels." if insecure else "Tokens sent only over HTTPS.",
        "Serve over HTTPS only and mark session cookies Secure."))
    return out
