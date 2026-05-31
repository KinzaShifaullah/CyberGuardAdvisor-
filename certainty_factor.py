# ============================================================
# certainty_factor.py – CyberGuard Advisor
# Implements proper Certainty Factor (CF) algebra as used in
# MYCIN expert system. Replaces simple weighted averaging.
#
# CF Combination Rules:
#   Both positive:  CF(A,B) = CF(A) + CF(B) * (1 - CF(A))
#   Both negative:  CF(A,B) = CF(A) + CF(B) * (1 + CF(A))
#   Mixed signs:    CF(A,B) = (CF(A) + CF(B)) / (1 - min(|CF(A)|,|CF(B)|))
# CF range: -1.0 to +1.0  (we store as 0-100, convert internally)
# ============================================================


def _combine_two(cf1: float, cf2: float) -> float:
    """Combine two CF values using MYCIN algebra. Values in [-1, 1]."""
    if cf1 >= 0 and cf2 >= 0:
        return cf1 + cf2 * (1 - cf1)
    elif cf1 < 0 and cf2 < 0:
        return cf1 + cf2 * (1 + cf1)
    else:
        denom = 1 - min(abs(cf1), abs(cf2))
        if denom == 0:
            return 0.0
        return (cf1 + cf2) / denom


def combine_certainty_factors(cf_list: list) -> float:
    """
    Combine a list of CF values (0-100 scale) using MYCIN CF algebra.
    Returns combined CF on 0-100 scale.
    """
    if not cf_list:
        return 0.0
    # Convert to -1..1 scale
    normalized = [(cf / 100.0) for cf in cf_list]
    result = normalized[0]
    for cf in normalized[1:]:
        result = _combine_two(result, cf)
    # Convert back to 0-100
    return round(min(max(result * 100, 0), 100), 1)


def get_cf_label(combined_cf: float) -> str:
    """Interpret combined CF score."""
    if combined_cf >= 85:
        return "CRITICAL"
    elif combined_cf >= 65:
        return "HIGH"
    elif combined_cf >= 40:
        return "MEDIUM"
    elif combined_cf > 0:
        return "LOW"
    return "SAFE"


def build_cf_report(triggered_rules: list) -> dict:
    """
    Build CF-based report per category using proper CF algebra.
    This is more academically rigorous than simple weighted averaging.
    """
    categories = ["password", "url", "phishing", "scam", "hygiene"]
    report = {}

    for cat in categories:
        threat_rules = [
            r for r in triggered_rules
            if r["category"] == cat and r["severity"] != "LOW"
        ]
        if not threat_rules:
            report[cat] = {"cf_score": 0.0, "label": "SAFE", "method": "CF Algebra"}
            continue

        # Weight CF by severity before combining
        severity_weight = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.65}
        weighted_cfs = [
            r["confidence"] * severity_weight.get(r["severity"], 0.5)
            for r in threat_rules
        ]
        combined = combine_certainty_factors(weighted_cfs)
        report[cat] = {
            "cf_score": combined,
            "label": get_cf_label(combined),
            "method": "MYCIN CF Algebra",
            "rules_combined": len(threat_rules),
        }

    # Overall: combine category CFs
    cat_cfs = [v["cf_score"] for v in report.values() if v["cf_score"] > 0]
    overall_cf = combine_certainty_factors(cat_cfs) if cat_cfs else 0.0
    report["overall"] = {
        "cf_score": overall_cf,
        "label": get_cf_label(overall_cf),
        "method": "MYCIN CF Algebra",
    }
    return report
