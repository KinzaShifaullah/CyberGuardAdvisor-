# ============================================================
# recommendation_engine.py – Cyber Guard Advisor
# Generates actionable security recommendations based on
# triggered rules and their severity levels.
# ============================================================

# ── Per-conclusion recommendations ──────────────────────────
RECOMMENDATIONS = {

# Password
"password_risk_critical": [
"Change this password IMMEDIATELY – it is critically weak.",
"Use a password manager (e.g. Bitwarden, KeePass) to generate strong passwords.",
"Your new password must be at least 12 characters long.",
"Include UPPERCASE, lowercase, digits, and special characters (!@#$%).",
"Never use common words, names, or keyboard patterns as passwords.",
],
"password_risk_high": [
"This password is too weak – replace it soon.",
"Aim for at least 12 characters with mixed character types.",
"Avoid sequences like '123', 'abc', or repeated characters.",
"Consider using a passphrase: e.g. 'Purple$Tiger!Runs7'.",
],
"password_risk_medium": [
"Your password could be stronger.",
"Add special characters and ensure mixed case letters.",
"Increase length to at least 12 characters.",
"Avoid using your name, birth year, or simple dictionary words.",
],
"password_risk_low": [
"Your password appears strong. Well done!",
"Remember to use a unique password for every account.",
"Store it safely using a reputable password manager.",
],

# URL
"url_risk_critical": [
"DO NOT visit this URL – it is highly suspicious.",
"This URL shows signs of phishing or malware distribution.",
"Report it to your organisation's security team immediately.",
"If you already clicked it, scan your device with an antivirus tool.",
],
"url_risk_high": [
"This URL has serious risk indicators – avoid visiting it.",
"Verify the domain name carefully – look for misspellings.",
"Never enter login credentials or personal data on suspicious sites.",
"Use Google Safe Browsing (safebrowsing.google.com) to check URLs.",
],
"url_risk_medium": [
"Exercise caution with this URL.",
"Always check that the site uses HTTPS before entering any data.",
"Hover over links to preview the real destination before clicking.",
"Avoid URLs received in unsolicited emails or messages.",
],
"url_risk_low": [
"This URL appears safe based on available indicators.",
"Always stay alert – even safe-looking URLs can be compromised.",
"Keep your browser updated for the latest security patches.",
],

# Phishing
"phishing_risk_critical": [
"This message is almost certainly a PHISHING ATTACK.",
"Do NOT click any links or open any attachments.",
"Do NOT provide any personal information, OTPs, or passwords.",
"Report the message to your email provider as phishing/spam.",
"If you responded, change affected passwords immediately.",
],
"phishing_risk_high": [
"This message shows strong phishing indicators.",
"Verify the sender's email address carefully – look for spoofing.",
"Contact the organisation directly (not through the message) to verify.",
"Never share OTPs, PINs, or passwords via email or SMS.",
],
"phishing_risk_medium": [
"This message has some suspicious characteristics.",
"Be cautious – do not act on urgent requests without verification.",
"Check the sender's domain matches the organisation's official domain.",
"When in doubt, contact the sender through an official channel.",
],
"phishing_risk_low": [
"This message shows no obvious phishing indicators.",
"Stay vigilant – always verify unexpected requests for action.",
"Enable email spam filters and report suspicious messages.",
],

# Scam
"scam_risk_critical": [
"This is almost certainly a SCAM. Do NOT engage.",
"Never send money, gift cards, or cryptocurrency to unknown parties.",
"Block and report the sender to relevant authorities.",
"If you have already sent money, contact your bank immediately.",
"Report to Pakistan FIA Cyber Crime Wing: www.fia.gov.pk",
],
"scam_risk_high": [
"This message has strong scam characteristics.",
"Legitimate companies never ask for advance payments or gift cards.",
"Research the organisation independently before taking any action.",
"Talk to a trusted friend or family member before responding.",
],
"scam_risk_medium": [
"Some scam indicators detected – proceed carefully.",
"Verify the offer/request through official channels.",
"Never provide financial information based on unsolicited contact.",
],
"scam_risk_low": [
"No major scam indicators detected.",
"Always research investment opportunities independently.",
"If pressured to decide quickly, that itself is a red flag.",
],

# Hygiene
"hygiene_risk_critical": [
"Your cyber hygiene practices pose CRITICAL risks.",
"Stop opening unknown email attachments immediately.",
"Never share passwords with anyone – not even colleagues.",
"Enable 2FA on all important accounts today.",
"Install reputable antivirus software immediately.",
],
"hygiene_risk_high": [
"Your cyber hygiene needs significant improvement.",
"Enable two-factor authentication (2FA) on all accounts.",
"Use a password manager to maintain unique passwords.",
"Use a VPN whenever connecting to public Wi-Fi.",
"Keep all software and operating systems updated.",
],
"hygiene_risk_medium": [
"Some hygiene improvements are recommended.",
"Enable automatic software updates on your devices.",
"Install and regularly update antivirus software.",
"Review your privacy settings on social media accounts.",
],
"hygiene_risk_low": [
"Your cyber hygiene practices are good!",
"Keep maintaining these good habits.",
"Stay informed about new cybersecurity threats.",
"Consider periodic security audits of your accounts.",
],
}

# ── General recommendations always shown ────────────────────
GENERAL_RECOMMENDATIONS = [
"Enable two-factor authentication (2FA) on all critical accounts.",
"Use a reputable password manager to store and generate passwords.",
"Keep all software, browsers, and operating systems up to date.",
"Install and maintain reputable antivirus / anti-malware software.",
"Back up important data regularly to an offline or encrypted location.",
"Be sceptical of unsolicited emails, messages, and phone calls.",
"Report suspicious activity to the FIA Cyber Crime Wing (Pakistan).",
]


def get_recommendations(triggered_rules: list) -> dict:
    """
    Generate recommendations based on triggered rule conclusions.
    Returns dict with 'specific' and 'general' lists.
    """
    specific = []
    seen_conclusions = set()

    for rule in triggered_rules:
        conclusion = rule["conclusion"]
        if conclusion not in seen_conclusions:
            seen_conclusions.add(conclusion)
            recs = RECOMMENDATIONS.get(conclusion, [])
            specific.extend(recs)

    # Deduplicate while preserving order
    unique_specific = list(dict.fromkeys(specific))

    general = [
        "Use a password manager to generate and store unique passwords for every account.",
        "Enable two-factor authentication on all accounts, especially email and banking.",
        "Keep all software, browsers, and operating systems updated to patch security vulnerabilities.",
        "Be cautious with unsolicited emails, messages, and links — verify sender identity first.",
        "Use a VPN when connecting to public Wi-Fi networks.",
        "Install reputable antivirus and anti-malware software and keep it updated.",
        "Regularly review account activity and report suspicious transactions immediately.",
        "Never share passwords, PINs, or OTPs with anyone, including people claiming to be support staff.",
    ]

    return {
        "specific": unique_specific,
        "general": general,
    }
