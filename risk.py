"""Risk Score = sum(vulnerability_weight x detection_result)  (paper, Sec. IV-D)."""
MODULE_WEIGHTS = {"authentication": 0.35, "session": 0.40, "proxy": 0.25}
BANDS = [(15, "CRITICAL", "Halt deployment; system at severe risk"),
         (9, "HIGH", "Urgent - multiple critical gaps present"),
         (5, "MEDIUM", "Immediate header/cookie remediation"),
         (0, "LOW", "Monitor; apply best-practice hardening")]


def classify(score: int):
    for lo, name, action in BANDS:
        if score >= lo:
            return name, action
    return "LOW", BANDS[-1][2]


def compute(findings: list) -> dict:
    score = sum(f.weight for f in findings if f.failed)
    band, action = classify(score)
    modules = {}
    for m, w in MODULE_WEIGHTS.items():
        fs = [f for f in findings if f.module == m]
        got = sum(f.weight for f in fs if f.failed)
        mx = sum(f.weight for f in fs) or 1
        modules[m] = {"weight": w, "score": got, "max": mx, "pct": round(100 * got / mx, 1)}
    index = round(sum(MODULE_WEIGHTS[m] * modules[m]["pct"] for m in modules), 1)
    return {"risk_score": score, "band": band, "action": action,
            "weighted_index": index, "modules": modules}
