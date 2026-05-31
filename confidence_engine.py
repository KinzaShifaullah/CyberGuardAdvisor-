# ============================================================
# confidence_engine.py – CyberGuard Advisor
# Calculates confidence scores per category and overall.
#
# Scoring logic:
#   1. Compute weighted average: CF(rule) * severity_weight
#   2. Apply severity floor: if CRITICAL fires, score >= 82
#      (prevents MEDIUM rules from diluting a CRITICAL finding)
#   3. Overall = average of non-zero category scores
# ============================================================

SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}

# Minimum score guaranteed when a severity level fires
SEVERITY_FLOOR = {"CRITICAL": 82.0, "HIGH": 66.0, "MEDIUM": 42.0, "LOW": 0.0}


def calculate_category_score(triggered_rules: list, category: str) -> float:
    """
    Calculate threat score for a category.
    Uses weighted average + severity floor escalation.
    A CRITICAL rule firing cannot be diluted below 82% by co-firing MEDIUM rules.
    """
    threat_rules = [
        r for r in triggered_rules
        if r["category"] == category and r["severity"] != "LOW"
    ]
    if not threat_rules:
        return 0.0

    total = sum(
        r["confidence"] * SEVERITY_WEIGHT[r["severity"]]
        for r in threat_rules
    )
    weighted_avg = total / len(threat_rules)

    # Escalation floor based on highest-severity rule that fired
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    top_rule = max(threat_rules, key=lambda r: sev_rank[r["severity"]])
    floor = SEVERITY_FLOOR[top_rule["severity"]]

    score = max(weighted_avg, floor)
    return min(round(score, 1), 100.0)


def calculate_overall_threat_score(triggered_rules: list) -> float:
    """Overall score = average of non-zero category scores."""
    if not triggered_rules:
        return 0.0
    categories = ["password", "url", "phishing", "scam", "hygiene"]
    cat_scores = [
        calculate_category_score(triggered_rules, cat)
        for cat in categories
        if calculate_category_score(triggered_rules, cat) > 0
    ]
    if not cat_scores:
        return 0.0
    return min(round(sum(cat_scores) / len(cat_scores), 1), 100.0)


def get_threat_label(score: float) -> str:
    if score >= 82:   return "CRITICAL"
    elif score >= 66: return "HIGH"
    elif score >= 42: return "MEDIUM"
    elif score > 0:   return "LOW"
    return "SAFE"


def get_score_color_tag(score: float) -> str:
    label = get_threat_label(score)
    return {"CRITICAL":"red","HIGH":"orange","MEDIUM":"yellow","LOW":"green","SAFE":"green"}.get(label,"white")


def build_score_report(triggered_rules: list) -> dict:
    categories = ["password", "url", "phishing", "scam", "hygiene"]
    report = {}
    for cat in categories:
        score = calculate_category_score(triggered_rules, cat)
        report[cat] = {"score": score, "label": get_threat_label(score)}
    overall = calculate_overall_threat_score(triggered_rules)
    report["overall"] = {"score": overall, "label": get_threat_label(overall)}
    return report
