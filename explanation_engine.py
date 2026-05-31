# ============================================================
# explanation_engine.py – Cyber Guard Advisor
# Generates human-readable explanations of the expert system's
# decisions: which rules fired, why, and what evidence was used.
# ============================================================

from confidence_engine import get_threat_label


CATEGORY_LABELS = {
    "password": "Password Security",
    "url":      "URL / Website Safety",
    "phishing": "Phishing Detection",
    "scam":     "Scam Detection",
    "hygiene":  "Cyber Hygiene",
}


def generate_explanation(triggered_rules: list, score_report: dict) -> dict:
    """
    Produce a structured explanation object.

    Returns:
    {
        "summary":        str   – one-line overall verdict,
        "overall_label":  str   – CRITICAL / HIGH / MEDIUM / LOW / SAFE,
        "overall_score":  float,
        "by_category":    { category: { rules: [...], narrative: str } },
        "triggered_list": str   – formatted bullet list of rule IDs + desc,
    }
    """
    overall = score_report.get("overall", {"score": 0, "label": "SAFE"})
    label = overall["label"]
    score = overall["score"]

    # ── Summary line ────────────────────────────────────────
    summary = _build_summary(label, score)

    # ── Per-category explanations ───────────────────────────
    by_category = {}
    for cat, cat_label in CATEGORY_LABELS.items():
        cat_rules = [r for r in triggered_rules if r["category"] == cat]
        if not cat_rules:
            continue
        cat_score = score_report.get(cat, {}).get("score", 0)
        cat_lvl = score_report.get(cat, {}).get("label", "SAFE")
        narrative = _build_category_narrative(cat, cat_rules, cat_lvl, cat_score)
        by_category[cat] = {
            "label":     cat_label,
            "level":     cat_lvl,
            "score":     cat_score,
            "rules":     cat_rules,
            "narrative": narrative,
        }

    # ── Flat triggered list (for display panel) ─────────────
    lines = []
    for rule in triggered_rules:
        lines.append(
            f"  [{rule['id']}] ({rule['severity']}, {rule['confidence']}%) "
            f"→ {rule['desc']}"
        )
    triggered_list = "\n".join(lines) if lines else "  No rules triggered."

    return {
        "summary":       summary,
        "overall_label": label,
        "overall_score": score,
        "by_category":   by_category,
        "triggered_list": triggered_list,
    }


def _build_summary(label: str, score: float) -> str:
    summaries = {
        "CRITICAL": (
            f"⛔  CRITICAL THREAT DETECTED  (Score: {score}%)\n"
            "Serious cybersecurity risks have been identified. "
            "Immediate action is required to protect your accounts and data."
        ),
        "HIGH": (
            f"🔴  HIGH RISK  (Score: {score}%)\n"
            "Significant security weaknesses detected. "
            "You should address these issues as soon as possible."
        ),
        "MEDIUM": (
            f"🟡  MEDIUM RISK  (Score: {score}%)\n"
            "Some security concerns were found. "
            "Review the recommendations below to improve your security posture."
        ),
        "LOW": (
            f"🟢  LOW RISK  (Score: {score}%)\n"
            "Minor security considerations noted. "
            "You are generally following good practices."
        ),
        "SAFE": (
            f"✅  SAFE  (Score: {score}%)\n"
            "No significant threats detected. "
            "Continue following good cybersecurity habits."
        ),
    }
    return summaries.get(label, f"Analysis complete. Score: {score}%")


def _build_category_narrative(
    category: str, rules: list, level: str, score: float
) -> str:
    """
    Build a paragraph explaining what was found in a category.
    """
    rule_ids = ", ".join(r["id"] for r in rules)
    top_rule = rules[0]  # highest severity (already sorted)

    narratives = {
        "password": (
            f"Password analysis triggered rule(s) {rule_ids}. "
            f"The primary concern is: '{top_rule['desc']}'. "
            f"Password risk level is {level} with a confidence of {score:.0f}%. "
            "A strong password uses 12+ characters with uppercase, lowercase, "
            "digits, and special characters."
        ),
        "url": (
            f"URL analysis triggered rule(s) {rule_ids}. "
            f"The main finding is: '{top_rule['desc']}'. "
            f"URL threat level is {level} with confidence {score:.0f}%. "
            "Always verify the domain name carefully before clicking."
        ),
        "phishing": (
            f"Message analysis triggered rule(s) {rule_ids}. "
            f"Primary phishing indicator: '{top_rule['desc']}'. "
            f"Phishing probability is {level} (confidence {score:.0f}%). "
            "Legitimate organisations never ask for passwords or OTPs by email."
        ),
        "scam": (
            f"Scam analysis triggered rule(s) {rule_ids}. "
            f"Key scam pattern found: '{top_rule['desc']}'. "
            f"Scam likelihood is {level} with confidence {score:.0f}%. "
            "If an offer seems too good to be true, it almost certainly is."
        ),
        "hygiene": (
            f"Cyber hygiene check triggered rule(s) {rule_ids}. "
            f"Main concern: '{top_rule['desc']}'. "
            f"Hygiene risk level is {level} (confidence {score:.0f}%). "
            "Good hygiene includes 2FA, unique passwords, and regular updates."
        ),
    }
    return narratives.get(
        category,
        f"Rules {rule_ids} triggered. Risk level: {level} ({score:.0f}%)."
    )


def format_full_report(explanation: dict, score_report: dict) -> str:
    """
    Produce a plain-text full report suitable for display in the GUI.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("       CYBER GUARD ADVISOR – THREAT ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append("")
    lines.append(explanation["summary"])
    lines.append("")

    lines.append("─" * 60)
    lines.append("  TRIGGERED RULES")
    lines.append("─" * 60)
    lines.append(explanation["triggered_list"])
    lines.append("")

    if explanation["by_category"]:
        lines.append("─" * 60)
        lines.append("  CATEGORY BREAKDOWN")
        lines.append("─" * 60)
        for cat, info in explanation["by_category"].items():
            lines.append(
                f"\n  [{info['level']}] {info['label']}  –  "
                f"Score: {info['score']:.0f}%"
            )
            lines.append(f"  {info['narrative']}")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)
