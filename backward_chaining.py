# ============================================================
# backward_chaining.py – CyberGuard Advisor
# Implements BACKWARD CHAINING (goal-driven inference).
#
# Forward chaining: facts → rules → conclusions  (data-driven)
# Backward chaining: goal → find rules → check conditions (goal-driven)
#
# Use case: "Is this a phishing attack?" → work backwards to
# find what evidence is needed to prove or disprove it.
# ============================================================

from knowledge_base import RULES


def get_rules_for_goal(goal_conclusion: str) -> list:
    """Find all rules that can prove a given goal/conclusion."""
    return [r for r in RULES if r["conclusion"] == goal_conclusion]


def backward_chain(goal: str, facts: dict, depth: int = 0, trace: list = None) -> dict:
    """
    Attempt to prove a goal using backward chaining.

    Args:
        goal: The conclusion to prove (e.g. 'phishing_risk_critical')
        facts: Known fact dictionary
        depth: Recursion depth (for trace display)
        trace: Reasoning trace list

    Returns:
        {
          'proved': bool,
          'confidence': float,
          'rules_used': list,
          'trace': list of reasoning steps
        }
    """
    if trace is None:
        trace = []

    indent = "  " * depth
    trace.append(f"{indent}GOAL: Prove '{goal}'")

    supporting_rules = get_rules_for_goal(goal)

    if not supporting_rules:
        trace.append(f"{indent}  → No rules found for this goal.")
        return {"proved": False, "confidence": 0.0, "rules_used": [], "trace": trace}

    proved_rules = []
    for rule in supporting_rules:
        trace.append(f"{indent}  Trying rule {rule['id']}: {rule['desc']}")
        all_conditions_met = True
        for condition in rule["conditions"]:
            fact_value = facts.get(condition, False)
            status = "TRUE" if fact_value else "FALSE"
            trace.append(f"{indent}    Condition '{condition}' → {status}")
            if not fact_value:
                all_conditions_met = False

        if all_conditions_met:
            trace.append(f"{indent}  ✓ Rule {rule['id']} PROVED (confidence: {rule['confidence']}%)")
            proved_rules.append(rule)
        else:
            trace.append(f"{indent}  ✗ Rule {rule['id']} NOT proved")

    if proved_rules:
        best = max(proved_rules, key=lambda r: r["confidence"])
        return {
            "proved": True,
            "confidence": best["confidence"],
            "rules_used": proved_rules,
            "trace": trace,
        }

    trace.append(f"{indent}  → Goal '{goal}' could NOT be proved.")
    return {"proved": False, "confidence": 0.0, "rules_used": [], "trace": trace}


# Pre-defined goals for each threat domain
GOALS = {
    "password": [
        "password_risk_critical",
        "password_risk_high",
        "password_risk_medium",
        "password_risk_low",
    ],
    "url": [
        "url_risk_critical",
        "url_risk_high",
        "url_risk_medium",
        "url_risk_low",
    ],
    "phishing": [
        "phishing_risk_critical",
        "phishing_risk_high",
        "phishing_risk_medium",
        "phishing_risk_low",
    ],
    "scam": [
        "scam_risk_critical",
        "scam_risk_high",
        "scam_risk_medium",
        "scam_risk_low",
    ],
    "hygiene": [
        "hygiene_risk_critical",
        "hygiene_risk_high",
        "hygiene_risk_medium",
        "hygiene_risk_low",
    ],
}


def run_backward_chaining(facts: dict, domain: str = None) -> dict:
    """
    Run backward chaining across all goals or a specific domain.
    Returns a summary of what was proved.
    """
    results = {}
    domains_to_check = [domain] if domain else list(GOALS.keys())

    for dom in domains_to_check:
        dom_results = []
        for goal in GOALS.get(dom, []):
            result = backward_chain(goal, facts)
            if result["proved"]:
                dom_results.append({
                    "goal": goal,
                    "confidence": result["confidence"],
                    "rules_used": result["rules_used"],
                    "trace": result["trace"],
                })
        results[dom] = dom_results

    return results
