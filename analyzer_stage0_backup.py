from urllib.parse import urlparse
import ipaddress
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "password",
    "account",
    "secure",
    "update",
    "confirm",
    "signin",
    "wallet",
]


def analyze_url(url):
    score = 0
    findings = []

    url = url.strip()

    # --------------------------------------------------
    # 1. Basic URL validation
    # --------------------------------------------------

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {
            "url": url,
            "score": 100,
            "risk": "HIGH RISK",
            "findings": ["Invalid or malformed URL."]
        }

    # --------------------------------------------------
    # 2. HTTPS check
    # --------------------------------------------------

    if parsed.scheme.lower() != "https":
        score += 15
        findings.append("The URL does not use HTTPS.")

    # --------------------------------------------------
    # 3. IP address instead of domain
    # --------------------------------------------------

    try:
        ipaddress.ip_address(hostname)
        score += 25
        findings.append("The destination uses an IP address instead of a domain name.")
    except ValueError:
        pass

    # --------------------------------------------------
    # 4. URL length
    # --------------------------------------------------

    if len(url) > 100:
        score += 10
        findings.append("The URL is unusually long.")

    # --------------------------------------------------
    # 5. Suspicious keywords
    # --------------------------------------------------

    lower_url = url.lower()

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lower_url:
            found_keywords.append(keyword)

    if found_keywords:
        score += min(25, len(found_keywords) * 5)

        findings.append(
            "Security-sensitive keywords detected: "
            + ", ".join(found_keywords)
            + "."
        )

    # --------------------------------------------------
    # 6. @ symbol
    # --------------------------------------------------

    if "@" in url:
        score += 20
        findings.append("The URL contains an '@' symbol, which can obscure the actual destination.")

    # --------------------------------------------------
    # 7. Excessive subdomains
    # --------------------------------------------------

    parts = hostname.split(".")

    if len(parts) >= 4:
        score += 10
        findings.append("The domain contains an unusually large number of subdomain levels.")

    # --------------------------------------------------
    # 8. Suspicious hyphen-heavy domain
    # --------------------------------------------------

    if hostname.count("-") >= 3:
        score += 10
        findings.append("The domain contains several hyphens, which can be a suspicious characteristic.")

    # --------------------------------------------------
    # 9. Suspicious-looking TLD
    # --------------------------------------------------

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".buzz",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
    ]

    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        score += 15
        findings.append("The domain uses a TLD that may warrant additional scrutiny.")

    # --------------------------------------------------
    # Cap score
    # --------------------------------------------------

    score = min(score, 100)

    if score <= 20:
        risk = "LOW RISK"
    elif score <= 50:
        risk = "CAUTION"
    else:
        risk = "HIGH RISK"

    if not findings:
        findings.append("No obvious indicators were detected by the current heuristic rules.")

    return {
        "url": url,
        "score": score,
        "risk": risk,
        "findings": findings,
    }