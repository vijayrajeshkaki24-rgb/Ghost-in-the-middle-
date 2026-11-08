"""Natural-language remediation via a local Ollama LLM, with a rule-based fallback."""
import requests


def _fallback(scan: dict) -> str:
    failed = [f for f in scan["findings"] if f["failed"]]
    if not failed:
        return "No AiTM-enabling weaknesses were detected. Keep monitoring and re-scan after changes."
    failed.sort(key=lambda f: -f["weight"])
    lines = [f"Overall risk: {scan['band']} (score {scan['risk_score']}). Priority fixes:"]
    for i, f in enumerate(failed, 1):
        lines.append(f"{i}. {f['title']} (weight {f['weight']}): {f['remediation']}")
    return "\n".join(lines)


def recommend(scan: dict, cfg) -> dict:
    failed = [f for f in scan["findings"] if f["failed"]]
    if not failed:
        return {"source": "rule-based", "text": _fallback(scan)}
    bullet = "\n".join(f"- {f['title']} (weight {f['weight']}): {f['detail']}" for f in failed)
    prompt = (
        "You are a web security engineer. A scanner found these weaknesses that enable "
        "Adversary-in-the-Middle (AiTM) session theft, which bypasses MFA:\n"
        f"{bullet}\n\nRisk band: {scan['band']}. Give a concise, prioritised remediation plan "
        "(max 8 bullets) with concrete header/cookie settings. Defensive advice only."
    )
    try:
        r = requests.post(f"{cfg.OLLAMA_URL}/api/generate",
                          json={"model": cfg.OLLAMA_MODEL, "prompt": prompt, "stream": False},
                          timeout=cfg.OLLAMA_TIMEOUT)
        r.raise_for_status()
        text = (r.json().get("response") or "").strip()
        if text:
            return {"source": "ollama", "text": text}
    except (requests.RequestException, ValueError):
        pass
    return {"source": "rule-based", "text": _fallback(scan)}
