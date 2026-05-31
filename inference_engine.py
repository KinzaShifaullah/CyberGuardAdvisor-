# ============================================================
# inference_engine.py – Cyber Guard Advisor
# Implements FORWARD CHAINING inference mechanism.
#
# Flow:
#   User Input Facts → Rule Matching → Rule Activation
#   → Conflict Resolution → Conclusions
# ============================================================

import re
from knowledge_base import (
    RULES, COMMON_PASSWORDS, SUSPICIOUS_URL_KEYWORDS,
    URL_SHORTENERS, SUSPICIOUS_TLDS, BANK_MIMICRY_KEYWORDS,
    URGENT_WORDS, PENALTY_WORDS, PRIZE_WORDS,
    SCAM_ADVANCE_FEE_WORDS, SCAM_INVESTMENT_WORDS,
)

# Severity order for conflict resolution (highest priority first)
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ──────────────────────────────────────────────────────────
# FACT EXTRACTION
# Extract boolean facts from raw user input
# ──────────────────────────────────────────────────────────

def extract_password_facts(password: str, username: str = "") -> dict:
    """
    Analyse a password string and return a dictionary of boolean facts.
    These facts are used by the inference engine to match rules.
    """
    facts = {}
    length = len(password)
    lower = password.lower()

    # Length checks
    facts["pwd_length_very_short"] = length < 6
    facts["pwd_length_short"] = length < 8
    facts["pwd_length_medium"] = 8 <= length <= 12
    facts["pwd_length_strong"] = length > 12

    # Character composition
    facts["has_uppercase"] = any(c.isupper() for c in password)
    facts["no_uppercase"] = not facts["has_uppercase"]
    facts["has_digit"] = any(c.isdigit() for c in password)
    facts["no_digit"] = not facts["has_digit"]

    special_chars = set("!@#$%^&*()_+-=[]{}|;:',.<>?/`~")
    facts["has_special_char"] = any(c in special_chars for c in password)
    facts["no_special_char"] = not facts["has_special_char"]

    # Only digits
    facts["only_digits"] = password.isdigit()

    # Common password check
    facts["common_password"] = lower in COMMON_PASSWORDS

    # Username in password
    if username:
        facts["contains_username"] = username.lower() in lower
    else:
        facts["contains_username"] = False

    # Sequential characters (abc, bcd, 123, 234 …)
    facts["sequential_chars"] = _has_sequential(lower)

    # Repeated characters (aaa, 111)
    facts["repeated_chars"] = bool(re.search(r"(.)\1{2,}", password))

    # Keyboard patterns
    keyboard_patterns = ["qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "2wsx"]
    facts["keyboard_pattern"] = any(kp in lower for kp in keyboard_patterns)

    # Contains a 4-digit year (19xx or 20xx)
    facts["contains_year"] = bool(re.search(r"(19|20)\d{2}", password))

    return facts


def _has_sequential(s: str) -> bool:
    """Return True if string contains 3+ sequential letters or digits."""
    for i in range(len(s) - 2):
        if (
            ord(s[i + 1]) == ord(s[i]) + 1 and
            ord(s[i + 2]) == ord(s[i]) + 2
        ):
            return True
    return False


def extract_url_facts(url: str) -> dict:
    """
    Analyse a URL string and return boolean facts.
    """
    facts = {}
    lower = url.lower()

    # Protocol
    facts["url_http"] = lower.startswith("http://")
    facts["url_https"] = lower.startswith("https://")

    # IP address in URL
    facts["url_has_ip"] = bool(
        re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", lower)
    )

    # Subdomain count (count dots before main domain)
    try:
        domain_part = re.sub(r"https?://", "", lower).split("/")[0]
        dot_count = domain_part.count(".")
        facts["url_many_subdomains"] = dot_count > 3
    except Exception:
        facts["url_many_subdomains"] = False

    # Suspicious keywords
    facts["url_suspicious_keywords"] = any(
        kw in lower for kw in SUSPICIOUS_URL_KEYWORDS
    )

    # Typosquatting: digits replacing letters (paypa1, g00gle)
    facts["url_typosquatting"] = bool(re.search(r"[a-z][0-9]|[0-9][a-z]", lower.split("/")[2].split(".")[0] if len(lower.split("/"))>2 else lower))

    # Length
    facts["url_very_long"] = len(url) > 100

    # @ symbol
    facts["url_has_at_symbol"] = "@" in url

    # URL shortener
    facts["url_shortener"] = any(sh in lower for sh in URL_SHORTENERS)

    # Suspicious TLD
    facts["url_suspicious_tld"] = any(
        lower.split("?")[0].endswith(tld) or f"{tld}/" in lower
        for tld in SUSPICIOUS_TLDS
    )

    # Double slash in path
    facts["url_double_slash"] = "//" in url[8:]  # ignore protocol slashes

    # Hex encoding
    facts["url_hex_encoded"] = bool(re.search(r"%[0-9a-fA-F]{2}", url))

    # Bank/payment domain mimicry
    facts["url_bank_mimicry"] = any(bk in lower for bk in BANK_MIMICRY_KEYWORDS)

    # Standard domain (simple heuristic: https + no suspicious signals)
    facts["url_standard_domain"] = (
        facts["url_https"] and
        not facts["url_has_ip"] and
        not facts["url_suspicious_keywords"] and
        not facts["url_typosquatting"] and
        not facts["url_bank_mimicry"]
    )

    # Redirect parameters
    facts["url_redirect_param"] = bool(
        re.search(r"[?&](url|redirect|next|goto|return)=", lower)
    )

    # Unusual port
    facts["url_unusual_port"] = bool(re.search(r":\d{4,5}/", url))

    return facts


def extract_message_facts(message: str) -> dict:
    """
    Analyse a message/email text and return boolean facts.
    """
    facts = {}
    lower = message.lower()

    # Urgent words
    facts["msg_urgent_words"] = any(w in lower for w in URGENT_WORDS)

    # Has URL/link
    facts["msg_has_link"] = bool(
        re.search(r"https?://|www\.|bit\.ly|tinyurl", lower)
    )

    # Personal info request
    personal_keywords = [
        "password", "credit card", "bank account", "ssn",
        "social security", "date of birth", "dob", "mother maiden",
        "pin", "cnic", "national id",
    ]
    facts["msg_asks_personal_info"] = any(kw in lower for kw in personal_keywords)

    # Account threat
    account_keywords = [
        "account suspended", "account blocked", "account disabled",
        "account restricted", "verify your account", "confirm your account",
        "account will be closed", "account termination",
    ]
    facts["msg_account_threat"] = any(kw in lower for kw in account_keywords)

    # Prize/lottery
    facts["msg_prize_claim"] = any(w in lower for w in PRIZE_WORDS)

    # Impersonates bank
    bank_keywords = [
        "bank", "paypal", "visa", "mastercard", "meezan",
        "hbl", "ubl", "easypaisa", "jazzcash", "western union",
    ]
    facts["msg_impersonates_bank"] = any(kw in lower for kw in bank_keywords)

    # Poor grammar (simple heuristic: excessive caps or missing spaces after punctuation)
    facts["msg_poor_grammar"] = (
        sum(1 for c in message if c.isupper()) / max(len(message), 1) > 0.4
        or bool(re.search(r"[.!?][A-Za-z]", message))
    )

    # Generic greeting
    generic_greetings = [
        "dear customer", "dear user", "dear member",
        "dear account holder", "dear valued",
    ]
    facts["msg_generic_greeting"] = any(g in lower for g in generic_greetings)

    # Legal threat
    legal_keywords = [
        "legal action", "court", "lawsuit", "prosecute",
        "arrest", "police", "fbi", "fia", "authorities",
    ]
    facts["msg_legal_threat"] = any(kw in lower for kw in legal_keywords)

    # Penalty words
    facts["msg_penalty_words"] = any(w in lower for w in PENALTY_WORDS)

    # Government impersonation
    govt_keywords = [
        "fbr", "fia", "nadra", "irs", "fbi", "government",
        "ministry", "tax authority", "immigration",
    ]
    facts["msg_impersonates_govt"] = any(kw in lower for kw in govt_keywords)

    # Sender mismatch (simple heuristic from text)
    facts["msg_sender_mismatch"] = bool(
        re.search(r"from:.*@(?!.*\bpaypal\b).*paypal", lower) or
        re.search(r"noreply@(?!.*\bbank\b).*bank", lower)
    )

    # Disaster / crisis hook
    disaster_keywords = ["covid", "pandemic", "earthquake", "flood", "disaster", "relief"]
    facts["msg_disaster_hook"] = any(kw in lower for kw in disaster_keywords)

    # OTP / password request
    facts["msg_asks_otp"] = bool(
        re.search(r"\botp\b|\bone.time\b|verification code|security code", lower)
    )

    # No red flags → all key indicators absent
    red_flags = [
        "msg_urgent_words", "msg_asks_personal_info", "msg_account_threat",
        "msg_prize_claim", "msg_legal_threat", "msg_penalty_words",
        "msg_asks_otp",
    ]
    facts["msg_no_red_flags"] = not any(facts.get(f, False) for f in red_flags)

    return facts


def extract_scam_facts(message: str) -> dict:
    """
    Analyse a message for scam-specific indicators.
    """
    facts = {}
    lower = message.lower()

    # Unrealistic financial reward
    facts["scam_unrealistic_reward"] = bool(
        re.search(r"\$[\d,]+\s*(million|billion|thousand)|crore|lakh", lower) or
        any(w in lower for w in ["free money", "make money fast", "earn millions"])
    )

    # Advance fee
    facts["scam_advance_fee"] = any(
        phrase in lower for phrase in SCAM_ADVANCE_FEE_WORDS
    )

    # Unsolicited win
    facts["scam_unsolicited_win"] = bool(
        re.search(r"you (have|'ve) won|you are (the |a )?winner", lower)
    )

    # Time pressure
    time_pressure_keywords = [
        "within 24 hours", "within 48 hours", "respond immediately",
        "expires today", "today only", "limited time", "don't delay",
        "respond now", "respond within",
    ]
    facts["scam_time_pressure"] = any(kw in lower for kw in time_pressure_keywords)

    # Easy money job
    easy_money_keywords = [
        "work from home", "no experience needed", "earn daily",
        "part time", "data entry", "typing job", "earn rs.",
        "daily income", "earn per click",
    ]
    facts["scam_easy_money_job"] = any(kw in lower for kw in easy_money_keywords)

    # Gift card / crypto payment
    gift_keywords = [
        "gift card", "itunes", "google play card", "amazon card",
        "send bitcoin", "send crypto", "wire transfer", "western union",
        "moneygram",
    ]
    facts["scam_gift_card_payment"] = any(kw in lower for kw in gift_keywords)

    # 419 / Nigerian prince pattern
    facts["scam_419_pattern"] = bool(
        re.search(
            r"prince|royal family|nigerian|foreign diplomat|"
            r"inheritance|estate|fund transfer|deceased",
            lower,
        )
    )

    # Investment fraud
    facts["scam_investment_fraud"] = any(
        phrase in lower for phrase in SCAM_INVESTMENT_WORDS
    )

    # Tech support scam
    facts["scam_tech_support"] = bool(
        re.search(
            r"microsoft support|apple support|tech support|"
            r"remote access|teamviewer|anydesk|your computer (is|has)",
            lower,
        )
    )

    # Romance fraud
    facts["scam_romance_fraud"] = bool(
        re.search(
            r"i love you|fallen in love|send me money|"
            r"stuck abroad|stuck in (hospital|airport)|medical emergency",
            lower,
        )
    )

    # Wire transfer
    facts["scam_wire_transfer"] = bool(
        re.search(r"wire transfer|bank wire|swift|iban|routing number", lower)
    )

    # No scam indicators
    scam_flags = [
        "scam_unrealistic_reward", "scam_advance_fee", "scam_unsolicited_win",
        "scam_gift_card_payment", "scam_419_pattern", "scam_investment_fraud",
        "scam_tech_support", "scam_romance_fraud", "scam_wire_transfer",
    ]
    facts["scam_no_indicators"] = not any(facts.get(f, False) for f in scam_flags)

    return facts


def extract_hygiene_facts(hygiene_answers: dict) -> dict:
    """
    Convert checklist answers about cyber hygiene to facts.
    hygiene_answers is a dict of {question_key: bool}
    """
    facts = {}
    # Map direct boolean answers
    facts["hygiene_password_reuse"] = hygiene_answers.get("password_reuse", False)
    facts["hygiene_no_2fa"] = hygiene_answers.get("no_2fa", False)
    facts["hygiene_public_wifi"] = hygiene_answers.get("public_wifi", False)
    facts["hygiene_no_updates"] = hygiene_answers.get("no_updates", False)
    facts["hygiene_no_antivirus"] = hygiene_answers.get("no_antivirus", False)
    facts["hygiene_opens_attachments"] = hygiene_answers.get("opens_attachments", False)
    facts["hygiene_shares_passwords"] = hygiene_answers.get("shares_passwords", False)

    bad_practices = [
        "hygiene_password_reuse", "hygiene_no_2fa", "hygiene_public_wifi",
        "hygiene_no_updates", "hygiene_no_antivirus",
        "hygiene_opens_attachments", "hygiene_shares_passwords",
    ]
    facts["hygiene_good_practices"] = not any(facts.get(f, False) for f in bad_practices)

    return facts


# ──────────────────────────────────────────────────────────
# FORWARD CHAINING INFERENCE ENGINE
# ──────────────────────────────────────────────────────────

def run_inference(facts: dict) -> list:
    """
    Apply forward chaining over the knowledge base.
    Returns list of triggered rule dictionaries (sorted by severity).
    """
    triggered = []

    for rule in RULES:
        # Check if ALL conditions for this rule are True in the fact base
        if all(facts.get(cond, False) for cond in rule["conditions"]):
            triggered.append(rule)

    # ── Conflict resolution: sort by severity (CRITICAL first) ──
    triggered.sort(key=lambda r: SEVERITY_ORDER[r["severity"]], reverse=True)

    return triggered


def resolve_conflicts(triggered_rules: list) -> dict:
    """
    Conflict resolution strategy: CRITICAL > HIGH > MEDIUM > LOW
    For each category, keep only the highest-severity conclusion.
    Returns dict: {category: highest_severity_rule}
    """
    category_winner = {}
    for rule in triggered_rules:
        cat = rule["category"]
        if cat not in category_winner:
            category_winner[cat] = rule
        else:
            current_sev = SEVERITY_ORDER[category_winner[cat]["severity"]]
            new_sev = SEVERITY_ORDER[rule["severity"]]
            if new_sev > current_sev:
                category_winner[cat] = rule
    return category_winner
