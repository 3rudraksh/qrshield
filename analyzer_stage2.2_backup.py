from pyexpat import features
from urllib.parse import urlparse, parse_qs, unquote
import ipaddress
import math
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "password",
    "passwd",
    "account",
    "secure",
    "update",
    "confirm",
    "wallet",
    "payment",
    "bank",
    "credential",
    "authenticate",
]


SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".buzz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
]


def calculate_entropy(value):
    """
    Calculate Shannon entropy for a string.

    Higher entropy can indicate a less human-readable
    or highly randomized string.
    """

    if not value:
        return 0.0

    frequency = {}

    for character in value:
        frequency[character] = frequency.get(character, 0) + 1

    entropy = 0.0
    length = len(value)

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

def decode_url_layers(url, max_layers=3):
    """
    Repeatedly percent-decode a URL and record each representation.

    Returns:
        list[str]: URL representations from original through
                   successive decoding layers.
    """

    layers = [url]
    current = url

    for _ in range(max_layers):
        decoded = unquote(current)

        if decoded == current:
            break

        layers.append(decoded)
        current = decoded

    return layers

def is_ip_address(hostname):
    """
    Determine whether the hostname is an IPv4 or IPv6 address.
    """

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def analyze_url(url):
    """
    Analyze a URL using explainable heuristic indicators.
    """

    score = 0
    findings = []
    features = []

    original_url = url.strip()

    if not original_url:
        return {
            "url": "",
            "score": 0,
            "risk": "INVALID",
            "findings": ["No URL was provided."],
            "features": []
        }

    # --------------------------------------------------
    # NORMALIZE URL
    # --------------------------------------------------

    if not re.match(r"^https?://", original_url, re.IGNORECASE):
        normalized_url = "http://" + original_url
    else:
        normalized_url = original_url

    # --------------------------------------------------
    # STAGE 2.1
    # MULTI-LAYER URL DECODING
    # --------------------------------------------------

    decode_layers = decode_url_layers(normalized_url)

    decoding_count = len(decode_layers) - 1

    features.append({
        "name": "Decoding Layers",
        "value": decoding_count
    })

    features.append({
        "name": "Decoded URL",
        "value": decode_layers[-1]
    })

    if decoding_count >= 1:

        score += 5

        findings.append({
            "severity": "medium",
            "indicator": "URL encoding detected",
            "detail": (
                f"The URL changed after percent-decoding "
                f"({decoding_count} decoding layer(s))."
            )
        })

    if decoding_count >= 2:

        score += 15

        findings.append({
            "severity": "high",
            "indicator": "Multiple URL-decoding layers detected",
            "detail": (
                "The URL required multiple percent-decoding "
                "operations to reach its final representation."
            )
        })

    # --------------------------------------------------
    # PARSE URL
    # --------------------------------------------------

    parsed = urlparse(normalized_url)

    hostname = parsed.hostname

    if not hostname:

        return {
            "url": normalized_url,
            "score": 100,
            "risk": "INVALID",
            "findings": [
                "The URL could not be parsed correctly."
            ],
            "features": []
        }

    hostname = hostname.lower()

    # --------------------------------------------------
    # BASIC URL INFORMATION
    # --------------------------------------------------

    features.append({
        "name": "Scheme",
        "value": parsed.scheme.upper()
    })

    features.append({
        "name": "Hostname",
        "value": hostname
    })

    features.append({
        "name": "Port",
        "value": parsed.port if parsed.port else "Default"
    })

    # --------------------------------------------------
    # HTTPS
    # --------------------------------------------------

    if parsed.scheme.lower() != "https":

        score += 15

        findings.append({
            "severity": "medium",
            "indicator": "HTTPS not detected",
            "detail": "The destination does not use HTTPS."
        })

    else:

        features.append({
            "name": "HTTPS",
            "value": "Enabled"
        })

    # --------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------

    if is_ip_address(hostname):

        score += 25

        findings.append({
            "severity": "high",
            "indicator": "IP address used as destination",
            "detail": (
                "The URL uses an IP address instead of "
                "a domain name."
            )
        })

        features.append({
            "name": "IP Address",
            "value": "Yes"
        })

    else:

        features.append({
            "name": "IP Address",
            "value": "No"
        })

    # --------------------------------------------------
    # URL LENGTH
    # --------------------------------------------------

    url_length = len(normalized_url)

    features.append({
        "name": "URL Length",
        "value": url_length
    })

    if url_length > 100:

        score += 10

        findings.append({
            "severity": "low",
            "indicator": "Unusually long URL",
            "detail": (
                f"The URL contains {url_length} characters."
            )
        })

    # --------------------------------------------------
    # HOSTNAME LENGTH
    # --------------------------------------------------

    hostname_length = len(hostname)

    features.append({
        "name": "Hostname Length",
        "value": hostname_length
    })

    if hostname_length > 50:

        score += 10

        findings.append({
            "severity": "medium",
            "indicator": "Long hostname",
            "detail": (
                "The hostname is unusually long."
            )
        })

    # --------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------

    hostname_parts = hostname.split(".")

    subdomain_count = max(
        0,
        len(hostname_parts) - 2
    )

    features.append({
        "name": "Subdomain Count",
        "value": subdomain_count
    })

    if subdomain_count >= 3:

        score += 10

        findings.append({
            "severity": "medium",
            "indicator": "Multiple subdomains",
            "detail": (
                f"The hostname contains approximately "
                f"{subdomain_count} subdomain levels."
            )
        })

    # --------------------------------------------------
    # PATH DEPTH
    # --------------------------------------------------

    path_parts = [
        part
        for part in parsed.path.split("/")
        if part
    ]

    path_depth = len(path_parts)

    features.append({
        "name": "Path Depth",
        "value": path_depth
    })

    if path_depth >= 5:

        score += 5

        findings.append({
            "severity": "low",
            "indicator": "Deep URL path",
            "detail": (
                "The destination contains many path levels."
            )
        })

    # --------------------------------------------------
    # QUERY PARAMETERS
    # --------------------------------------------------

    query_parameters = parse_qs(parsed.query)

    parameter_count = len(query_parameters)

    features.append({
        "name": "Query Parameters",
        "value": parameter_count
    })

    if parameter_count >= 5:

        score += 5

        findings.append({
            "severity": "low",
            "indicator": "Many query parameters",
            "detail": (
                f"The URL contains {parameter_count} "
                f"query parameters."
            )
        })

    # --------------------------------------------------
    # FRAGMENT
    # --------------------------------------------------

    if parsed.fragment:

        features.append({
            "name": "Fragment",
            "value": "Present"
        })

    else:

        features.append({
            "name": "Fragment",
            "value": "None"
        })

    # --------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------

    # Userinfo / @ deception detection
    if "@" in normalized_url:
        try:
            parsed = urlparse(normalized_url)

            username = parsed.username
            hostname = parsed.hostname

            if username:
                score += 20

                features.append({
                    "name": "URL Userinfo",
                    "value": username
                })

                features.append({
                    "name": "Actual Hostname",
                    "value": hostname
                })

                findings.append({
                    "severity": "high",
                    "message": (
                        f"URL contains userinfo before @. "
                        f"Actual destination hostname is {hostname}"
                    )
                })

            else:
                score += 10

                features.append({
                    "name": "At Symbol",
                    "value": True
                })

                findings.append({
                    "severity": "medium",
                    "message": "URL contains @ symbol"
                })

        except ValueError:
            score += 20

            findings.append({
                "severity": "high",
                "message": "Malformed URL contains @ symbol"
            })

    # --------------------------------------------------
    # PERCENT ENCODING
    # --------------------------------------------------

    encoded_matches = re.findall(
        r"%[0-9a-fA-F]{2}",
        normalized_url
    )

    encoded_count = len(encoded_matches)

    features.append({
        "name": "Percent Encoded Characters",
        "value": encoded_count
    })

    if encoded_count >= 5:

        score += 10

        findings.append({
            "severity": "medium",
            "indicator": "Heavy URL encoding",
            "detail": (
                f"The URL contains {encoded_count} "
                f"percent-encoded sequences."
            )
        })

    # --------------------------------------------------
    # ENCODED CONTENT
    # --------------------------------------------------

    if decoding_count > 0:

        features.append({
            "name": "Encoded Content",
            "value": "Present"
        })

    else:

        features.append({
            "name": "Encoded Content",
            "value": "None detected"
        })

    # --------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------

    lower_url = normalized_url.lower()

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in lower_url:
            found_keywords.append(keyword)

    if found_keywords:

        keyword_score = min(
            25,
            len(found_keywords) * 5
        )

        score += keyword_score

        findings.append({
            "severity": "medium",
            "indicator": "Security-sensitive keywords",
            "detail": ", ".join(found_keywords)
        })

    features.append({
        "name": "Suspicious Keywords",
        "value": (
            ", ".join(found_keywords)
            if found_keywords
            else "None"
        )
    })

    # --------------------------------------------------
    # HYPHENS
    # --------------------------------------------------

    hyphen_count = hostname.count("-")

    features.append({
        "name": "Hostname Hyphens",
        "value": hyphen_count
    })

    if hyphen_count >= 3:

        score += 10

        findings.append({
            "severity": "low",
            "indicator": "Hyphen-heavy hostname",
            "detail": (
                f"The hostname contains "
                f"{hyphen_count} hyphens."
            )
        })

    # --------------------------------------------------
    # DIGITS
    # --------------------------------------------------

    digit_count = sum(
        character.isdigit()
        for character in hostname
    )

    features.append({
        "name": "Hostname Digits",
        "value": digit_count
    })

    if digit_count >= 5 and not is_ip_address(hostname):

        score += 5

        findings.append({
            "severity": "low",
            "indicator": "High digit count in hostname",
            "detail": (
                f"The hostname contains "
                f"{digit_count} digits."
            )
        })

    # --------------------------------------------------
    # SUSPICIOUS TLD
    # --------------------------------------------------

    matched_tld = None

    for tld in SUSPICIOUS_TLDS:

        if hostname.endswith(tld):

            matched_tld = tld
            break

    if matched_tld:

        score += 15

        findings.append({
            "severity": "medium",
            "indicator": "Suspicious-looking TLD",
            "detail": (
                f"The hostname ends with {matched_tld}."
            )
        })

    features.append({
        "name": "TLD Indicator",
        "value": (
            matched_tld
            if matched_tld
            else "No match"
        )
    })

    # --------------------------------------------------
    # HOSTNAME ENTROPY
    # --------------------------------------------------

    entropy = calculate_entropy(hostname)

    features.append({
        "name": "Hostname Entropy",
        "value": round(entropy, 2)
    })

    if entropy > 4.2 and hostname_length > 20:

        score += 5

        findings.append({
            "severity": "low",
            "indicator": "High hostname complexity",
            "detail": (
                "The hostname contains a relatively high "
                "degree of character variation."
            )
        })

    # --------------------------------------------------
    # NORMALIZE SCORE
    # --------------------------------------------------

    score = min(score, 100)

    # --------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------

    if score <= 20:

        risk = "LOW RISK"

    elif score <= 50:

        risk = "CAUTION"

    else:

        risk = "HIGH RISK"

    # --------------------------------------------------
    # NO FINDINGS
    # --------------------------------------------------

    if not findings:

        findings.append({
            "severity": "info",
            "indicator": "No obvious indicators detected",
            "detail": (
                "The current heuristic engine did not "
                "identify suspicious characteristics."
            )
        })

    # --------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------

    return {
        "url": normalized_url,
        "score": score,
        "risk": risk,
        "findings": findings,
        "features": features
    }