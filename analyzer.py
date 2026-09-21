from pyexpat import features
from urllib.parse import urlparse, parse_qs, unquote
import ipaddress
import math
import re
import socket

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

def analyze_hostname_structure(hostname):
    """
    Analyze hostname structure for suspicious subdomain patterns.
    Returns structural information without making reputation claims.
    """

    if not hostname:
        return {
            "subdomain_count": 0,
            "labels": [],
            "suspicious_subdomain": False,
            "reasons": []
        }

    hostname = hostname.lower().strip(".")
    labels = hostname.split(".")

    # Ignore the final domain components when looking at subdomains.
    # This is a structural heuristic, not full Public Suffix List parsing.
    subdomains = labels[:-2] if len(labels) >= 2 else []

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "signin",
        "support",
        "bank",
        "wallet",
        "payment"
    ]

    suspicious_subdomains = [
        label for label in subdomains
        if any(keyword in label for keyword in suspicious_keywords)
    ]

    reasons = []

    if len(subdomains) >= 3:
        reasons.append("Multiple subdomain levels detected")

    if suspicious_subdomains:
        reasons.append(
            "Security-sensitive keywords appear in subdomains"
        )

    return {
        "subdomain_count": len(subdomains),
        "labels": labels,
        "suspicious_subdomain": bool(suspicious_subdomains),
        "suspicious_subdomains": suspicious_subdomains,
        "reasons": reasons
    }

def analyze_punycode(hostname):
    """
    Analyze a hostname for punycode/Internationalised domain names (IDN)

    IDNs start with the prefix "xn--"
    presence of punycode can indicate an attempt to obfuscate the true domain name
    but is not inherently malicious.
    This function checks for the presence of punycode and returns relevant information.
    """

    if not hostname:
        return {
            "detected" : False,
            "labels" : [],
            "punycodeLabels" : [],
        }
    
    hostname = hostname.lower().strip(".")
    labels = hostname.split(".")

    punycode_labels = [label for label in labels
    if label.startswith("xn--")]

    return {
        "detected" : bool(punycode_labels),
        "labels" : labels,
        "punycode_labels" : punycode_labels
    }

def analyze_port(parsed):
    """
    Analyze the explicit port used by a URL.

    Returns structural information about whether a port was
    explicitly specified and whether it is commonly associated
    with the URL scheme.
    """

    try:
        port = parsed.port
    except ValueError:
        return {
            "explicit": True,
            "port": None,
            "valid": False,
            "reason": "Invalid port specification"
        }

    if port is None:
        return {
            "explicit": False,
            "port": None,
            "valid": True,
            "reason": "No explicit port"
        }

    default_ports = {
        "http": 80,
        "https": 443
    }

    expected_port = default_ports.get(parsed.scheme.lower())

    return {
        "explicit": True,
        "port": port,
        "valid": True,
        "default": port == expected_port,
        "expected_port": expected_port,
        "reason": (
            "Default port"
            if port == expected_port
            else "Non-default port"
        )
    }

def analyze_path_query_deception(parsed):
    """
    Analyze URL path and query components for deception indicators.

    This detects suspicious security-related language and
    redirect-style query parameters.

    Detection alone does not imply maliciousness.
    """

    path = parsed.path or ""
    query = parsed.query or ""

    security_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "password",
        "credential",
        "payment",
        "wallet",
        "bank"
    ]

    path_lower = path.lower()

    suspicious_path_keywords = [
        keyword
        for keyword in security_keywords
        if keyword in path_lower
    ]

    redirect_keywords = [
        "redirect",
        "url",
        "target",
        "next",
        "return",
        "returnurl",
        "continue",
        "dest",
        "destination"
    ]

    query_lower = query.lower()

    redirect_parameters = [
        keyword
        for keyword in redirect_keywords
        if f"{keyword}=" in query_lower
    ]

    return {
        "path": path,
        "query": query,
        "suspicious_path_keywords": suspicious_path_keywords,
        "redirect_parameters": redirect_parameters,
        "suspicious": bool(
            suspicious_path_keywords or redirect_parameters
        )
    }

def analyze_obfuscation_combination(
    decoding_count=0,
    userinfo_detected=False,
    suspicious_subdomain=False,
    punycode_detected=False,
    non_default_port=False,
    suspicious_path=False,
    redirect_parameters=False
):
    """
    Analyze combinations of URL obfuscation and deception indicators.

    Multiple indicators occurring together may represent a stronger
    structural deception signal than any single indicator alone.

    This does not prove maliciousness.
    """

    indicators = []

    if decoding_count > 0:
        indicators.append("URL decoding")

    if userinfo_detected:
        indicators.append("userinfo / @")

    if suspicious_subdomain:
        indicators.append("suspicious subdomain")

    if punycode_detected:
        indicators.append("Punycode / IDN")

    if non_default_port:
        indicators.append("non-default port")

    if suspicious_path:
        indicators.append("suspicious path")

    if redirect_parameters:
        indicators.append("redirect parameter")

    count = len(indicators)

    if count >= 4:
        level = "high"
    elif count >= 2:
        level = "medium"
    else:
        level = "low"

    return {
        "count": count,
        "level": level,
        "indicators": indicators
    }

def resolve_hostname(hostname):
    """
    Resolve a hostname using the system DNS resolver.

    Returns:
        {
            "resolved": True/False,
            "addresses": [...],
            "ipv4": [...],
            "ipv6": [...],
            "error": None or error message
        }
    """

    if not hostname:
        return {
            "resolved": False,
            "addresses": [],
            "ipv4": [],
            "ipv6": [],
            "error": "No hostname provided"
        }

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        addresses = set()

        for result in results:
            address = result[4][0]
            addresses.add(address)

        ipv4_addresses = []
        ipv6_addresses = []

        for address in sorted(addresses):
            try:
                ip = ipaddress.ip_address(address)

                if ip.version == 4:
                    ipv4_addresses.append(address)
                elif ip.version == 6:
                    ipv6_addresses.append(address)

            except ValueError:
                continue

        all_addresses = ipv4_addresses + ipv6_addresses

        return {
            "resolved": bool(all_addresses),
            "addresses": all_addresses,
            "ipv4": ipv4_addresses,
            "ipv6": ipv6_addresses,
            "error": None
        }

    except socket.gaierror as error:
        return {
            "resolved": False,
            "addresses": [],
            "ipv4": [],
            "ipv6": [],
            "error": str(error)
        }

    except socket.timeout:
        return {
            "resolved": False,
            "addresses": [],
            "ipv4": [],
            "ipv6": [],
            "error": "DNS resolution timed out"
        }

    except OSError as error:
        return {
            "resolved": False,
            "addresses": [],
            "ipv4": [],
            "ipv6": [],
            "error": str(error)
        }

def analyze_dns(hostname):
    """
    Analyze DNS information for a hostname.

    Returns:
        {
            "hostname": ...,
            "status": ...,
            "is_ip": True/False,
            "resolved": True/False,
            "addresses": [...],
            "ipv4": [...],
            "ipv6": [...],
            "address_count": ...,
            "error": ...
        }
    """

    if not hostname:
        return {
            "hostname": hostname,
            "status": "NO_HOSTNAME",
            "is_ip": False,
            "resolved": False,
            "addresses": [],
            "ipv4": [],
            "ipv6": [],
            "address_count": 0,
            "ipv4_count": 0,
            "ipv6_count": 0,
            "error": "No hostname provided"
        }

    if is_ip_address(hostname):
        return {
            "hostname": hostname,
            "status": "IP_LITERAL",
            "is_ip": True,
            "resolved": False,
            "addresses": [hostname],
            "ipv4": [hostname] if "." in hostname else [],
            "ipv6": [hostname] if ":" in hostname else [],
            "address_count": 1,
            "ipv4_count": 1 if "." in hostname else 0,
            "ipv6_count": 1 if ":" in hostname else 0,
            "error": None
        }

    dns_result = resolve_hostname(hostname)

    if dns_result["resolved"]:
        status = "RESOLVED"
    else:
        status = "DNS_FAILURE"

    return {
        "hostname": hostname,
        "status": status,
        "is_ip": False,
        "resolved": dns_result["resolved"],
        "addresses": dns_result["addresses"],
        "ipv4": dns_result["ipv4"],
        "ipv6": dns_result["ipv6"],
        "address_count": len(dns_result["addresses"]),
        "ipv4_count": len(dns_result["ipv4"]),
        "ipv6_count": len(dns_result["ipv6"]),
        "error": dns_result["error"]
    }

def build_dns_features(dns_analysis):
    """
    Convert detailed DNS analysis into a compact feature set
    for the main URL analysis engine.
    """

    return {
        "status": dns_analysis["status"],
        "address_count": dns_analysis["address_count"],
        "ipv4_count": dns_analysis["ipv4_count"],
        "ipv6_count": dns_analysis["ipv6_count"],
        "has_ipv4": dns_analysis["ipv4_count"] > 0,
        "has_ipv6": dns_analysis["ipv6_count"] > 0,
        "resolution_failed": dns_analysis["status"] == "DNS_FAILURE"
    }

def evaluate_dns_risk(dns_features):
    """
    Evaluate DNS-related risk indicators.

    Returns:
        {
            "score": int,
            "findings": [...]
        }
    """

    score = 0
    findings = []

    if dns_features["status"] == "DNS_FAILURE":
        score += 10

        findings.append({
            "severity": "low",
            "message": "Hostname could not be resolved through DNS"
        })

    return {
        "score": score,
        "findings": findings
    }

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

    # Port analysis
    port_analysis = analyze_port(parsed)

    if not port_analysis["valid"]:
        score += 15

        features.append({
            "name": "Port",
            "value": "Invalid"
        })

        findings.append({
            "severity": "medium",
            "message": "URL contains an invalid port specification"
        })

    elif port_analysis["explicit"]:

        features.append({
            "name": "Explicit Port",
            "value": port_analysis["port"]
        })

        if not port_analysis["default"]:
            score += 5

            findings.append({
                "severity": "low",
                "message": (
                    f"URL uses non-default port "
                    f"{port_analysis['port']} for {parsed.scheme.upper()}"
                )
            })

    punycode_analysis = analyze_punycode(hostname)

    if punycode_analysis["detected"]:
        score += 10

        features.append({
        "name": "Punycode / IDN",
        "value": punycode_analysis["punycode_labels"]
        })

        findings.append({
            "severity": "medium",
            "message": (
                "Hostname contains Punycode / Internationalized "
                "Domain Name (IDN) labels"
            )
        })

        # Hostname / subdomain structure analysis
    hostname_analysis = analyze_hostname_structure(hostname)

    features.append({
        "name": "Hostname Labels",
        "value": hostname_analysis["labels"]
    })

    # features.append({
    #     "name": "Subdomain Count",
    #     "value": hostname_analysis["subdomain_count"]
    # })

    if hostname_analysis["suspicious_subdomain"]:
        score += 10

        findings.append({
            "severity": "medium",
            "message": (
                "Security-sensitive keywords appear in the hostname's "
                "subdomain structure"
            )
        })

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

        # Path and query deception analysis
    path_query_analysis = analyze_path_query_deception(parsed)

    if path_query_analysis["suspicious_path_keywords"]:

        features.append({
            "name": "Suspicious Path Keywords",
            "value": path_query_analysis["suspicious_path_keywords"]
        })

        findings.append({
            "severity": "low",
            "message": (
                "URL path contains security-sensitive keywords: "
                + ", ".join(
                    path_query_analysis["suspicious_path_keywords"]
                )
            )
        })

    if path_query_analysis["redirect_parameters"]:
        score += 10

        features.append({
            "name": "Redirect Parameters",
            "value": path_query_analysis["redirect_parameters"]
        })

        findings.append({
            "severity": "medium",
            "message": (
                "URL query contains redirect-style parameters: "
                + ", ".join(
                    path_query_analysis["redirect_parameters"]
                )
            )
        })

    hostname = hostname.lower()

    # STAGE 3 / DNS INTELLIGENCE
    dns_analysis = analyze_dns(hostname)
    dns_features = build_dns_features(dns_analysis)

    dns_risk = evaluate_dns_risk(dns_features)
    score += dns_risk["score"]

    for finding in dns_risk["findings"]:
        findings.append(finding)

    # --------------------------------------------------
    # BASIC URL INFORMATION
    # --------------------------------------------------

    if port_analysis["explicit"] and port_analysis["valid"]:
        port_value = port_analysis["port"]
    elif not port_analysis["valid"]:
        port_value = "Invalid"  
    else:
        port_value = "Default"

    features.append({
    "name": "Port",
    "value": port_value
    })



    features.append({
        "name": "Scheme",
        "value": parsed.scheme.upper()
    })

    features.append({
        "name": "Hostname",
        "value": hostname
    })

    features.append({
        "name": "DNS Intelligence",
        "value": dns_features
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
    decoding_count = len(decode_layers) - 1
    obfuscation_analysis = analyze_obfuscation_combination(
        decoding_count=decoding_count,
        userinfo_detected=(
            "@" in normalized_url
            and bool(parsed.username)
        ),
        suspicious_subdomain=hostname_analysis["suspicious_subdomain"],
        punycode_detected=punycode_analysis["detected"],
        non_default_port=(
            port_analysis["explicit"]
            and port_analysis["valid"]
            and not port_analysis["default"]
        ),
        suspicious_path=bool(
            path_query_analysis["suspicious_path_keywords"]
        ),
        redirect_parameters=bool(
            path_query_analysis["redirect_parameters"]
        )
    )    
    features.append({
    "name": "Obfuscation Combination",
    "value": {
        "count": obfuscation_analysis["count"],
        "indicators": obfuscation_analysis["indicators"],
        "level": obfuscation_analysis["level"]
        }
    })

    if obfuscation_analysis["count"] >= 4:
        score += 10

        findings.append({
            "severity": "high",
            "message": (
                "Multiple URL obfuscation and deception techniques "
                "occur together"
            )
        })

    elif obfuscation_analysis["count"] >= 2:
        score += 5

        findings.append({
            "severity": "medium",
            "message": (
                "Multiple URL obfuscation and deception indicators "
                "occur together"
            )
        })    
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

            # Obfuscation combination analysis

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