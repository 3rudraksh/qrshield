from pyexpat import features
import urllib.parse
from urllib.parse import urlparse, unquote, urljoin, urlsplit, parse_qs
import ipaddress
import math
import re
import socket
import ssl
from cryptography import x509
import datetime
import urllib.request
import os
import json


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

REDIRECT_STATUS_CODES = {
    301,
    302,
    303,
    307,
    308
}

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

def get_tls_connection(hostname, port=443, timeout=5):
    """
    Establish a TLS connection to a hostname.

    Returns:
        {
            "connected": True/False,
            "hostname": hostname,
            "port": port,
            "error": None or error message
        }
    """

    if not hostname:
        return {
            "connected": False,
            "hostname": hostname,
            "port": port,
            "error": "No hostname provided"
        }

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=timeout
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ):

                return {
                    "connected": True,
                    "hostname": hostname,
                    "port": port,
                    "error": None
                }

    except (socket.timeout, TimeoutError):
        return {
            "connected": False,
            "hostname": hostname,
            "port": port,
            "error": "TLS connection timed out"
        }

    except ssl.SSLError as error:
        return {
            "connected": False,
            "hostname": hostname,
            "port": port,
            "error": str(error)
        }

    except OSError as error:
        return {
            "connected": False,
            "hostname": hostname,
            "port": port,
            "error": str(error)
        }

def get_tls_certificate(hostname, port=443, timeout=5):
    """
    Retrieve the TLS certificate presented by a hostname.

    The certificate is retrieved in binary DER form so that QRShield
    can inspect certificates even when normal certificate validation
    would reject them.

    Returns:
        {
            "retrieved": True/False,
            "hostname": hostname,
            "port": port,
            "certificate": certificate_bytes_or_None,
            "error": None or error message
        }
    """

    if not hostname:
        return {
            "retrieved": False,
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "error": "No hostname provided"
        }

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # This connection is for certificate inspection only.
        # QRShield does not trust the certificate here.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (hostname, port),
            timeout=timeout
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as tls_socket:

                certificate = tls_socket.getpeercert(
                    binary_form=True
                )

                return {
                    "retrieved": bool(certificate),
                    "hostname": hostname,
                    "port": port,
                    "certificate": certificate,
                    "error": None if certificate else "Empty TLS certificate"
                }

    except (socket.timeout, TimeoutError):
        return {
            "retrieved": False,
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "error": "TLS connection timed out"
        }

    except ssl.SSLError as error:
        return {
            "retrieved": False,
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "error": str(error)
        }

    except OSError as error:
        return {
            "retrieved": False,
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "error": str(error)
        }
    
def extract_certificate_metadata(certificate):
    """
    Extract useful metadata from a TLS certificate.

    The certificate is expected to be in DER binary form.

    Returns:
        {
            "common_name": ...,
            "issuer": ...,
            "valid_from": ...,
            "valid_until": ...,
            "dns_names": [...],
            "ip_addresses": [...],
            "dns_name_count": ...,
            "ip_address_count": ...
        }
    """

    if not certificate:
        return {
            "common_name": None,
            "issuer": None,
            "valid_from": None,
            "valid_until": None,
            "dns_names": [],
            "ip_addresses": [],
            "dns_name_count": 0,
            "ip_address_count": 0
        }

    try:
        cert = x509.load_der_x509_certificate(certificate)

        common_name = None

        try:
            common_name = cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )[0].value
        except IndexError:
            pass

        issuer_parts = cert.issuer.get_attributes_for_oid(
            x509.NameOID.ORGANIZATION_NAME
        )

        issuer = ", ".join(
            attribute.value
            for attribute in issuer_parts
        ) if issuer_parts else None

        dns_names = []
        ip_addresses = []

        try:
            san_extension = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )

            for name in san_extension.value:

                if isinstance(name, x509.DNSName):
                    dns_names.append(name.value)

                elif isinstance(name, x509.IPAddress):
                    ip_addresses.append(str(name.value))

        except x509.ExtensionNotFound:
            pass

        # Keep the same string format expected by
        # analyze_certificate_validity().
        valid_from = cert.not_valid_before_utc.strftime(
            "%b %d %H:%M:%S %Y GMT"
        )

        valid_until = cert.not_valid_after_utc.strftime(
            "%b %d %H:%M:%S %Y GMT"
        )

        return {
            "common_name": common_name,
            "issuer": issuer,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "dns_names": dns_names,
            "ip_addresses": ip_addresses,
            "dns_name_count": len(dns_names),
            "ip_address_count": len(ip_addresses)
        }

    except Exception:
        return {
            "common_name": None,
            "issuer": None,
            "valid_from": None,
            "valid_until": None,
            "dns_names": [],
            "ip_addresses": [],
            "dns_name_count": 0,
            "ip_address_count": 0
        }
    
def analyze_certificate_validity(valid_from, valid_until):
    """
    Analyze the validity period of a TLS certificate.

    Returns:
        {
            "status": "VALID" / "EXPIRED" / "NOT_YET_VALID" / "INVALID",
            "valid_from": ...,
            "valid_until": ...,
            "days_remaining": ...,
            "error": None or error message
        }
    """

    if not valid_from or not valid_until:
        return {
            "status": "INVALID",
            "valid_from": valid_from,
            "valid_until": valid_until,
            "days_remaining": None,
            "error": "Certificate validity dates are missing"
        }

    try:
        date_format = "%b %d %H:%M:%S %Y GMT"

        start_date = datetime.datetime.strptime(
            valid_from,
            date_format
        )

        end_date = datetime.datetime.strptime(
            valid_until,
            date_format
        )

        current_date = datetime.datetime.utcnow()

        if current_date < start_date:
            status = "NOT_YET_VALID"
        elif current_date > end_date:
            status = "EXPIRED"
        else:
            status = "VALID"

        days_remaining = (end_date - current_date).days

        return {
            "status": status,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "days_remaining": days_remaining,
            "error": None
        }

    except ValueError as error:
        return {
            "status": "INVALID",
            "valid_from": valid_from,
            "valid_until": valid_until,
            "days_remaining": None,
            "error": str(error)
        }

def analyze_certificate_identity(hostname, certificate_metadata):
    """
    Determine whether a TLS certificate identifies the requested hostname.

    Returns:
        {
            "hostname": ...,
            "matches": True/False,
            "matched_name": ...,
            "match_type": "DNS" / "IP" / "NONE",
            "error": None or error message
        }
    """

    if not hostname:
        return {
            "hostname": hostname,
            "matches": False,
            "matched_name": None,
            "match_type": "NONE",
            "error": "No hostname provided"
        }

    dns_names = certificate_metadata.get("dns_names", [])
    ip_addresses = certificate_metadata.get("ip_addresses", [])

        # IP address matching
        # IP address matching
    if is_ip_address(hostname):
        try:
            requested_ip = ipaddress.ip_address(hostname)

            for certificate_ip in ip_addresses:
                try:
                    certificate_ip_object = ipaddress.ip_address(
                        certificate_ip
                    )

                    if requested_ip == certificate_ip_object:
                        return {
                            "hostname": hostname,
                            "matches": True,
                            "matched_name": certificate_ip,
                            "match_type": "IP",
                            "error": None
                        }

                except ValueError:
                    continue

        except ValueError:
            pass

        return {
            "hostname": hostname,
            "matches": False,
            "matched_name": None,
            "match_type": "NONE",
            "error": "IP address not present in certificate SANs"
        }
    # Exact DNS match
    if hostname in dns_names:
        return {
            "hostname": hostname,
            "matches": True,
            "matched_name": hostname,
            "match_type": "DNS",
            "error": None
        }

    # Wildcard matching
# Wildcard matching
    for name in dns_names:
        if name.startswith("*."):
            suffix = name[2:]

            if hostname.endswith("." + suffix):
                hostname_labels = hostname.split(".")
                suffix_labels = suffix.split(".")

                if len(hostname_labels) == len(suffix_labels) + 1:
                    return {
                        "hostname": hostname,
                        "matches": True,
                        "matched_name": name,
                        "match_type": "DNS",
                        "error": None
                    }
            
    return {
        "hostname": hostname,
        "matches": False,
        "matched_name": None,
        "match_type": "NONE",
        "error": "Hostname not present in certificate SANs"
    }

def build_tls_features(
    certificate_metadata,
    validity_analysis,
    identity_analysis
):
    """
    Convert detailed TLS analysis into a compact feature set
    for the main URL analysis engine.
    """

    return {
        "certificate_present": (
            certificate_metadata.get("common_name") is not None
            or certificate_metadata.get("issuer") is not None
            or certificate_metadata.get("valid_from") is not None
            or certificate_metadata.get("valid_until") is not None
            or certificate_metadata.get("dns_name_count", 0) > 0
            or certificate_metadata.get("ip_address_count", 0) > 0
        ),
        "common_name": certificate_metadata.get("common_name"),
        "issuer": certificate_metadata.get("issuer"),
        "validity_status": validity_analysis["status"],
        "days_remaining": validity_analysis["days_remaining"],
        "identity_matches": identity_analysis["matches"],
        "identity_match_type": identity_analysis["match_type"],
        "matched_name": identity_analysis["matched_name"],
        "dns_name_count": certificate_metadata["dns_name_count"],
        "ip_address_count": certificate_metadata["ip_address_count"]
    }

def evaluate_tls_risk(tls_features):
    """
    Evaluate TLS-related risk indicators.

    Returns:
        {
            "score": int,
            "findings": [...]
        }
    """

    score = 0
    findings = []

    if not tls_features["certificate_present"]:
        score += 15

        findings.append({
            "severity": "medium",
            "message": "No TLS certificate was retrieved"
        })

        return {
            "score": score,
            "findings": findings
        }

    if tls_features["validity_status"] == "EXPIRED":
        score += 20

        findings.append({
            "severity": "high",
            "message": "TLS certificate has expired"
        })

    elif tls_features["validity_status"] == "NOT_YET_VALID":
        score += 20

        findings.append({
            "severity": "high",
            "message": "TLS certificate is not yet valid"
        })

    elif tls_features["validity_status"] == "INVALID":
        score += 15

        findings.append({
            "severity": "medium",
            "message": "TLS certificate validity could not be verified"
        })

    if not tls_features["identity_matches"]:
        score += 25

        findings.append({
            "severity": "high",
            "message": "TLS certificate does not match the requested hostname"
        })

    return {
        "score": score,
        "findings": findings
    }

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl
    ):
        return None

def make_http_request(url, timeout=5):
    """
    Make an HTTP request to a URL without automatically
    following redirects.

    Returns:
        {
            "success": True/False,
            "url": ...,
            "status_code": ...,
            "location": ...,
            "headers": ...,
            "error": ...
        }
    """

    if not url:
        return {
            "success": False,
            "url": url,
            "status_code": None,
            "location": None,
            "headers": {},
            "error": "No URL provided"
        }
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname

    network_check = is_unsafe_network_target(hostname)

    if network_check["unsafe"]:
        return {
            "success": False,
            "url": url,
            "status_code": None,
            "location": None,
            "headers": {},
            "error": (
                "Blocked network target: "
                + network_check["reason"]
            )
        }

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "QRShield/1.0"
        }
    )

    opener = urllib.request.build_opener(
        NoRedirectHandler()
    )
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "QRShield/1.0"
        }
    )

    opener = urllib.request.build_opener(
        NoRedirectHandler()
    )


    try:
        response = opener.open(
            request,
            timeout=timeout
        )

        return {
            "success": True,
            "url": response.geturl(),
            "status_code": response.status,
            "location": response.headers.get("Location"),
            "headers": dict(response.headers),
            "error": None
        }

    except urllib.error.HTTPError as error:
        return {
            "success": True,
            "url": error.geturl(),
            "status_code": error.code,
            "location": error.headers.get("Location"),
            "headers": dict(error.headers),
            "error": None
        }

    except (urllib.error.URLError, socket.timeout, TimeoutError) as error:
        return {
            "success": False,
            "url": url,
            "status_code": None,
            "location": None,
            "headers": {},
            "error": str(error)
        }

    except OSError as error:
        return {
            "success": False,
            "url": url,
            "status_code": None,
            "location": None,
            "headers": {},
            "error": str(error)
        }

def analyze_redirect_response(response):
    """
    Analyze a single HTTP response for redirect behavior.

    Returns:
        {
            "is_redirect": True/False,
            "status_code": ...,
            "location": ...,
            "has_location": True/False
        }
    """

    if not response:
        return {
            "is_redirect": False,
            "status_code": None,
            "location": None,
            "has_location": False
        }

    status_code = response.get("status_code")
    location = response.get("location")

    is_redirect = (
        status_code in REDIRECT_STATUS_CODES
        and bool(location)
    )

    return {
        "is_redirect": is_redirect,
        "status_code": status_code,
        "location": location,
        "has_location": bool(location)
    }

def validate_redirect_target(url):
    """
    Validate a redirect target before following it.
    """

    if not url:
        return {
            "valid": False,
            "reason": "Empty redirect target"
        }

    try:
        parsed = urllib.parse.urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return {
                "valid": False,
                "reason": "Unsupported redirect scheme"
            }

        if not parsed.hostname:
            return {
                "valid": False,
                "reason": "Redirect target has no hostname"
            }

        return {
            "valid": True,
            "reason": None
        }

    except ValueError:
        return {
            "valid": False,
            "reason": "Malformed redirect target"
        }

def follow_redirect_chain(url, max_redirects=5, timeout=5):
    """
    Follow HTTP redirects manually.

    Returns:
        {
            "original_url": ...,
            "final_url": ...,
            "redirect_count": ...,
            "loop_detected": ...,
            "max_redirects_reached": ...,
            "completed": ...,
            "hops": [...],
            "error": ...
        }
    """

    if not url:
        return {
            "original_url": url,
            "final_url": None,
            "redirect_count": 0,
            "loop_detected": False,
            "max_redirects_reached": False,
            "completed": False,
            "hops": [],
            "error": "No URL provided"
        }

    current_url = url
    visited_urls = set()
    hops = []

    for _ in range(max_redirects + 1):

        # Loop protection
        if current_url in visited_urls:
            return {
                "original_url": url,
                "final_url": current_url,
                "redirect_count": len(hops),
                "loop_detected": True,
                "max_redirects_reached": False,
                "completed": False,
                "hops": hops,
                "error": "Redirect loop detected"
            }

        visited_urls.add(current_url)

        # Make request without automatically following redirects
        response = make_http_request(
            current_url,
            timeout=timeout
        )

        # Request failed
        if not response.get("success"):
            return {
                "original_url": url,
                "final_url": current_url,
                "redirect_count": len(hops),
                "loop_detected": False,
                "max_redirects_reached": False,
                "completed": False,
                "hops": hops,
                "error": response.get("error")
            }

        redirect = analyze_redirect_response(response)

        # Record this HTTP hop
        hops.append({
            "url": current_url,
            "status_code": redirect["status_code"],
            "location": redirect["location"],
            "is_redirect": redirect["is_redirect"]
        })

        # Not a redirect = final destination
        if not redirect["is_redirect"]:
            return {
                "original_url": url,
                "final_url": current_url,
                "redirect_count": len(hops) - 1,
                "loop_detected": False,
                "max_redirects_reached": False,
                "completed": True,
                "hops": hops,
                "error": None
            }

            # Resolve relative Location values
            # Resolve relative Location values
        next_url = urllib.parse.urljoin(
            current_url,
            redirect["location"]
        )

        # Validate redirect destination
        target_validation = validate_redirect_target(next_url)

        if not target_validation["valid"]:
            return {
                "original_url": url,
                "final_url": current_url,
                "redirect_count": len(hops),
                "loop_detected": False,
                "max_redirects_reached": False,
                "completed": False,
                "hops": hops,
                "error": target_validation["reason"]
            }

        current_url = next_url

    # Hard redirect limit reached
    return {
        "original_url": url,
        "final_url": current_url,
        "redirect_count": len(hops),
        "loop_detected": False,
        "max_redirects_reached": True,
        "completed": False,
        "hops": hops,
        "error": "Maximum redirect limit reached"
    }

def evaluate_redirect_risk(redirect_analysis):
    """
    Evaluate security risk from redirect behavior.

    Returns:
        {
            "score": int,
            "findings": [...]
        }
    """

    score = 0
    findings = []

    if not redirect_analysis:
        return {
            "score": 0,
            "findings": []
        }

    redirect_count = redirect_analysis.get("redirect_count", 0)
    cross_domain = redirect_analysis.get(
        "cross_domain_redirect",
        False
    )
    https_downgrade = redirect_analysis.get(
        "https_downgrade",
        False
    )

    # Multiple redirects
    if redirect_count >= 3:
        score += 10
        findings.append(
            "URL uses multiple redirects"
        )

    # Cross-domain redirect
    if cross_domain:
        score += 10
        findings.append(
            "Redirect chain crosses between different domains"
        )

    # HTTPS → HTTP downgrade
    if https_downgrade:
        score += 20
        findings.append(
            "Redirect chain downgrades from HTTPS to HTTP"
        )

    return {
        "score": score,
        "findings": findings
    }


def analyze_redirect_chain(chain):
    """
    Analyze a completed redirect chain for security-relevant behavior.

    Returns:
        {
            "redirect_count": ...,
            "domains": [...],
            "cross_domain_redirect": ...,
            "https_downgrade": ...,
            "final_domain": ...,
            "findings": [...]
        }
    """

    if not chain:
        return {
            "redirect_count": 0,
            "domains": [],
            "cross_domain_redirect": False,
            "https_downgrade": False,
            "final_domain": None,
            "findings": []
        }

    hops = chain.get("hops", [])

    domains = []
    cross_domain_redirect = False
    https_downgrade = False
    findings = []

    previous_url = None

    for hop in hops:
        current_url = hop.get("url")

        if not current_url:
            continue

        parsed_current = urllib.parse.urlparse(current_url)
        current_domain = parsed_current.hostname

        if current_domain and current_domain not in domains:
            domains.append(current_domain)

        if previous_url:
            parsed_previous = urllib.parse.urlparse(previous_url)

            previous_domain = parsed_previous.hostname

            if (
                previous_domain
                and current_domain
                and previous_domain.lower() != current_domain.lower()
            ):
                cross_domain_redirect = True

            if (
                parsed_previous.scheme.lower() == "https"
                and parsed_current.scheme.lower() == "http"
            ):
                https_downgrade = True

        previous_url = current_url

    final_url = chain.get("final_url")

    final_domain = None

    if final_url:
        final_domain = urllib.parse.urlparse(
            final_url
        ).hostname

    if cross_domain_redirect:
        findings.append(
            "Redirect chain crosses between different domains"
        )

    if https_downgrade:
        findings.append(
            "Redirect chain downgrades from HTTPS to HTTP"
        )

    return {
        "redirect_count": chain.get("redirect_count", 0),
        "domains": domains,
        "cross_domain_redirect": cross_domain_redirect,
        "https_downgrade": https_downgrade,
        "final_domain": final_domain,
        "findings": findings
    }

def classify_redirect_chain(redirect_analysis):
    """
    Classify the overall redirect behavior.
    """

    if not redirect_analysis:
        return "NO_REDIRECT_DATA"

    if redirect_analysis.get("https_downgrade"):
        return "HTTPS_DOWNGRADE"

    if redirect_analysis.get("cross_domain_redirect"):
        return "CROSS_DOMAIN"

    redirect_count = redirect_analysis.get("redirect_count", 0)

    if redirect_count >= 3:
        return "MULTIPLE_REDIRECTS"

    if redirect_count > 0:
        return "SINGLE_REDIRECT"

    return "NO_REDIRECT"


def is_unsafe_network_target(hostname):
    """
    Determine whether a hostname resolves to a local,
    private, loopback, link-local, or otherwise non-public
    IP address.

    Returns:
        {
            "unsafe": True/False,
            "addresses": [...],
            "reason": ...
        }
    """

    if not hostname:
        return {
            "unsafe": True,
            "addresses": [],
            "reason": "No hostname provided"
        }

    # Direct IP address
    try:
        ip = ipaddress.ip_address(hostname)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return {
                "unsafe": True,
                "addresses": [str(ip)],
                "reason": "Non-public IP address"
            }

        return {
            "unsafe": False,
            "addresses": [str(ip)],
            "reason": None
        }

    except ValueError:
        pass

    # Hostname → IP resolution
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        addresses = []

        for result in results:
            address = result[4][0]

            if address not in addresses:
                addresses.append(address)

        for address in addresses:
            ip = ipaddress.ip_address(address)

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                return {
                    "unsafe": True,
                    "addresses": addresses,
                    "reason": "Hostname resolves to a non-public IP address"
                }

        return {
            "unsafe": False,
            "addresses": addresses,
            "reason": None
        }

    except socket.gaierror:
        return {
            "unsafe": True,
            "addresses": [],
            "reason": "Hostname could not be resolved"
        }

    except (socket.timeout, TimeoutError):
        return {
            "unsafe": True,
            "addresses": [],
            "reason": "Hostname resolution timed out"
        }

    except OSError as exc:
        return {
            "unsafe": True,
            "addresses": [],
            "reason": f"Network resolution error: {exc}"
        }

def query_urlhaus(url, timeout=5):
    """
    Query URLhaus for intelligence about a URL.
    """

    auth_key = os.getenv("URLHAUS_AUTH_KEY")

    if not auth_key:
        return {
            "source": "URLhaus",
            "status": "NOT_CONFIGURED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "URLhaus API key not configured"
        }

    if not url:
        return {
            "source": "URLhaus",
            "status": "INVALID_INPUT",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "No URL provided"
        }

    try:
        data = urllib.parse.urlencode({
            "url": url
        }).encode()

        request = urllib.request.Request(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data=data,
            headers={
                "Auth-Key": auth_key,
                "User-Agent": "QRShield/1.0"
            },
            method="POST"
        )

        with urllib.request.urlopen(
            request,
            timeout=timeout
        ) as response:

            response_data = json.loads(
                response.read().decode("utf-8")
            )

        query_status = response_data.get("query_status")

        if query_status == "ok":
            return {
                "source": "URLhaus",
                "status": "FOUND",
                "malicious": True,
                "url": response_data.get("url", url),
                "threat": response_data.get("threat"),
                "error": None
            }

        if query_status == "no_results":
            return {
                "source": "URLhaus",
                "status": "NOT_FOUND",
                "malicious": False,
                "url": url,
                "threat": None,
                "error": None
            }

        return {
            "source": "URLhaus",
            "status": "UNKNOWN",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": query_status
        }

    except urllib.error.HTTPError as error:
        return {
            "source": "URLhaus",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": f"HTTP {error.code}"
        }

    except urllib.error.URLError as error:
        return {
            "source": "URLhaus",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": str(error.reason)
        }

    except (socket.timeout, TimeoutError):
        return {
            "source": "URLhaus",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "Request timed out"
        }

    except (OSError, json.JSONDecodeError) as error:
        return {
            "source": "URLhaus",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": str(error)
        }

def query_google_safe_browsing(url, timeout=5):
    """
    Query Google Safe Browsing for URL reputation.
    """

    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    if not api_key:
        return {
            "source": "Google Safe Browsing",
            "status": "NOT_CONFIGURED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "Google Safe Browsing API key not configured"
        }

    if not url:
        return {
            "source": "Google Safe Browsing",
            "status": "INVALID_INPUT",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "No URL provided"
        }

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/"
        f"threatMatches:find?key={api_key}"
    )

    payload = {
        "client": {
            "clientId": "qrshield",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": [
                "ANY_PLATFORM"
            ],
            "threatEntryTypes": [
                "URL"
            ],
            "threatEntries": [
                {
                    "url": url
                }
            ]
        }
    }

    try:
        data = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "QRShield/1.0"
            },
            method="POST"
        )

        with urllib.request.urlopen(
            request,
            timeout=timeout
        ) as response:

            response_data = json.loads(
                response.read().decode("utf-8")
            )

        matches = response_data.get("matches", [])

        if matches:
            threats = [
                match.get("threatType")
                for match in matches
                if match.get("threatType")
            ]

            return {
                "source": "Google Safe Browsing",
                "status": "FOUND",
                "malicious": True,
                "url": url,
                "threat": threats,
                "error": None
            }

        return {
            "source": "Google Safe Browsing",
            "status": "NOT_FOUND",
            "malicious": False,
            "url": url,
            "threat": None,
            "error": None
        }

    except urllib.error.HTTPError as error:
        return {
            "source": "Google Safe Browsing",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": f"HTTP {error.code}"
        }

    except urllib.error.URLError as error:
        return {
            "source": "Google Safe Browsing",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": str(error.reason)
        }

    except (socket.timeout, TimeoutError):
        return {
            "source": "Google Safe Browsing",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "Request timed out"
        }

    except (OSError, json.JSONDecodeError) as error:
        return {
            "source": "Google Safe Browsing",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": str(error)
        }

def evaluate_reputation_consensus(sources):
    """
    Evaluate agreement between reputation providers.
    """

    if not sources:
        return {
            "consensus": "NO_DATA",
            "confidence": "LOW",
            "threat_sources": 0,
            "checked_sources": 0
        }

    checked_sources = len(sources)

    threat_sources = sum(
        1
        for source in sources
        if source.get("status") == "FOUND"
    )

    available_sources = sum(
        1
        for source in sources
        if source.get("status") in ("FOUND", "NOT_FOUND")
    )

    if threat_sources == checked_sources:
        return {
            "consensus": "CONFIRMED_THREAT",
            "confidence": "HIGH",
            "threat_sources": threat_sources,
            "checked_sources": checked_sources
        }

    if threat_sources > 0 and available_sources > threat_sources:
        return {
            "consensus": "PARTIAL_THREAT",
            "confidence": "MEDIUM",
            "threat_sources": threat_sources,
            "checked_sources": checked_sources
        }

    if available_sources == checked_sources:
        return {
            "consensus": "NO_THREAT_MATCH",
            "confidence": "LOW",
            "threat_sources": 0,
            "checked_sources": checked_sources
        }

    return {
        "consensus": "INSUFFICIENT_DATA",
        "confidence": "LOW",
        "threat_sources": threat_sources,
        "checked_sources": checked_sources
    }

def evaluate_risk_engine(
    score,
    findings,
    reputation_analysis=None,
    dns_analysis=None,
    tls_features=None,
    redirect_analysis=None
):
    """
    Build a centralized risk profile from QRShield security evidence.
    """

    score = min(max(score, 0), 100)

    high_findings = sum(
        1 for finding in findings
        if isinstance(finding, dict)
        and finding.get("severity") == "high"
    )

    medium_findings = sum(
        1 for finding in findings
        if isinstance(finding, dict)
        and finding.get("severity") == "medium"
    )

    low_findings = sum(
        1 for finding in findings
        if isinstance(finding, dict)
        and finding.get("severity") == "low"
    )

    # --------------------------------------------------
    # Reputation evidence
    # --------------------------------------------------

    reputation_confirmed = False

    if reputation_analysis:
        reputation_confirmed = (
            reputation_analysis.get("reputation") == "MALICIOUS"
        )

    # --------------------------------------------------
    # Confidence assessment
    # --------------------------------------------------

    available_evidence = 0
    unavailable_evidence = 0

    # Reputation
    if reputation_analysis:
        reputation_consensus = reputation_analysis.get(
            "consensus",
            {}
        )

        if reputation_consensus.get("consensus") in (
            "CONFIRMED_THREAT",
            "NO_THREAT_MATCH"
        ):
            available_evidence += 1
        else:
            unavailable_evidence += 1
    else:
        unavailable_evidence += 1

    # DNS
    if dns_analysis:
        if dns_analysis.get("status") in (
            "RESOLVED",
            "IP_LITERAL"
        ):
            available_evidence += 1
        else:
            unavailable_evidence += 1
    else:
        unavailable_evidence += 1

    # TLS
    if tls_features:
        if tls_features.get("certificate_present"):
            available_evidence += 1
        else:
            unavailable_evidence += 1
    else:
        unavailable_evidence += 1

    # Redirect
    if redirect_analysis:
        if redirect_analysis.get("completed"):
            available_evidence += 1
        else:
            unavailable_evidence += 1
    else:
        unavailable_evidence += 1

    total_evidence_sources = (
        available_evidence + unavailable_evidence
    )

    if total_evidence_sources == 0:
        confidence = "LOW"

    elif available_evidence == total_evidence_sources:
        confidence = "HIGH"

    elif available_evidence >= 2:
        confidence = "MEDIUM"

    else:
        confidence = "LOW"

    # --------------------------------------------------
    # DNS evidence
    # --------------------------------------------------

    dns_status = None

    if dns_analysis:
        dns_status = dns_analysis.get("status")

    # --------------------------------------------------
    # TLS evidence
    # --------------------------------------------------

    tls_status = None
    tls_identity_match = None

    if tls_features:
        tls_status = tls_features.get("validity_status")
        tls_identity_match = tls_features.get("identity_matches")

    # --------------------------------------------------
    # Redirect evidence
    # --------------------------------------------------

    redirect_count = 0
    redirect_cross_domain = False
    redirect_https_downgrade = False

    if redirect_analysis:
        redirect_count = redirect_analysis.get(
            "redirect_count",
            0
        )

        redirect_cross_domain = redirect_analysis.get(
            "cross_domain_redirect",
            False
        )

        redirect_https_downgrade = redirect_analysis.get(
            "https_downgrade",
            False
        )

    # --------------------------------------------------
    # Evidence correlation
    # --------------------------------------------------

    correlated_signals = []

    if dns_status == "DNS_FAILURE":
        correlated_signals.append("DNS failure")

    if tls_identity_match is False:
        correlated_signals.append("TLS identity mismatch")

    if tls_status in ("EXPIRED", "NOT_YET_VALID"):
        correlated_signals.append("Invalid TLS validity")

    if redirect_cross_domain:
        correlated_signals.append("Cross-domain redirect")

    if redirect_https_downgrade:
        correlated_signals.append("HTTPS downgrade")

    if redirect_count >= 3:
        correlated_signals.append("Multiple redirects")

    if reputation_confirmed:
        correlated_signals.append("Threat intelligence match")

    if medium_findings >= 2:
        correlated_signals.append("Multiple medium-severity findings")

    if high_findings >= 1:
        correlated_signals.append("High-severity finding")

    correlation_count = len(correlated_signals)

    if correlation_count >= 3:
        correlation_level = "HIGH"

    elif correlation_count == 2:
        correlation_level = "MEDIUM"

    elif correlation_count == 1:
        correlation_level = "LOW"

    else:
        correlation_level = "NONE"


    # --------------------------------------------------
    # Risk level
    # --------------------------------------------------

    if score <= 20:
        risk = "LOW RISK"
    elif score <= 50:
        risk = "CAUTION"
    else:
        risk = "HIGH RISK"

    # --------------------------------------------------
    # Risk basis
    # --------------------------------------------------

    if reputation_confirmed:
        risk_basis = "External threat intelligence"

    elif redirect_https_downgrade:
        risk_basis = "HTTPS downgrade detected"

    elif tls_identity_match is False:
        risk_basis = "TLS certificate identity mismatch"

    elif tls_status in ("EXPIRED", "NOT_YET_VALID"):
        risk_basis = "Invalid TLS certificate validity"

    elif redirect_cross_domain:
        risk_basis = "Cross-domain redirect behavior"

    elif redirect_count >= 3:
        risk_basis = "Multiple redirects"

    elif dns_status == "DNS_FAILURE":
        risk_basis = "DNS resolution failure"

    elif high_findings >= 2:
        risk_basis = "Multiple high-severity indicators"

    elif high_findings == 1:
        risk_basis = "High-severity indicator"

    elif medium_findings >= 2:
        risk_basis = "Multiple medium-severity indicators"

    elif score > 0:
        risk_basis = "Heuristic indicators"

    else:
        risk_basis = "No significant indicators"

    return {
        "score": score,
        "risk": risk,
        "risk_basis": risk_basis,
        "confidence": confidence,
        "evidence": {
            "high": high_findings,
            "medium": medium_findings,
            "low": low_findings
        },
        "reputation_confirmed": reputation_confirmed,
        "signals": {
            "dns_status": dns_status,
            "tls_status": tls_status,
            "tls_identity_match": tls_identity_match,
            "redirect_count": redirect_count,
            "redirect_cross_domain": redirect_cross_domain,
            "redirect_https_downgrade": redirect_https_downgrade
        },
        "correlation": {
            "level": correlation_level,
            "count": correlation_count,
            "signals": correlated_signals
        }

    }

def build_finding_explanation(finding):
    """
    Convert a QRShield finding into a structured explanation.
    """

    if not isinstance(finding, dict):
        return {
            "title": "Security finding",
            "severity": "info",
            "what": str(finding),
            "why_it_matters": "QRShield detected an item that requires attention.",
            "user_action": "Review the destination before interacting with it."
        }

    severity = finding.get("severity", "info")
    message = finding.get("message")
    indicator = finding.get("indicator")
    detail = finding.get("detail")

    title = indicator or "Security finding"
    what = detail or message or "QRShield detected a security-related indicator."

    if severity == "high":
        why_it_matters = (
            "This indicator can represent a significant security risk "
            "and should be investigated before interacting with the destination."
        )

        user_action = (
            "Do not interact with the destination until its legitimacy "
            "has been verified."
        )

    elif severity == "medium":
        why_it_matters = (
            "This indicator does not prove that the destination is malicious, "
            "but it increases the need for caution."
        )

        user_action = (
            "Review the destination carefully before continuing."
        )

    elif severity == "low":
        why_it_matters = (
            "This is a weaker indicator that provides additional context "
            "about the destination."
        )

        user_action = (
            "Consider this indicator together with the other findings."
        )

    else:
        why_it_matters = (
            "QRShield detected an informational security indicator."
        )

        user_action = (
            "Review the finding together with the overall risk assessment."
        )

    return {
        "title": title,
        "severity": severity,
        "what": what,
        "why_it_matters": why_it_matters,
        "user_action": user_action
    }

def build_overall_explanation(risk_analysis):
    """
    Build a human-readable explanation of the overall risk assessment.
    """

    if not isinstance(risk_analysis, dict):
        return "QRShield could not generate an overall risk explanation."

    risk = risk_analysis.get("risk", "UNKNOWN")
    risk_basis = risk_analysis.get(
        "risk_basis",
        "Unknown"
    )

    correlation = risk_analysis.get(
        "correlation",
        {}
    )

    correlation_count = correlation.get(
        "count",
        0
    )

    if (
        risk == "LOW RISK"
        and risk_basis == "No significant indicators"
    ):
        return (
            "QRShield did not detect significant security "
            "indicators for this destination."
        )

    basis_text = {
        "External threat intelligence":
            "external threat intelligence identified the destination",
        "HTTPS downgrade detected":
            "an HTTPS downgrade was detected",
        "TLS certificate identity mismatch":
            "a TLS certificate identity mismatch was detected",
        "Invalid TLS certificate validity":
            "the TLS certificate has an invalid validity state",
        "Cross-domain redirect behavior":
            "cross-domain redirect behavior was detected",
        "Multiple redirects":
            "multiple redirects were detected",
        "DNS resolution failure":
            "DNS resolution failed for the hostname",
        "Multiple high-severity indicators":
            "multiple high-severity indicators were detected",
        "High-severity indicator":
            "a high-severity indicator was detected",
        "Multiple medium-severity indicators":
            "multiple medium-severity indicators were detected",
        "Heuristic indicators":
            "heuristic security indicators were detected"
    }

    explanation_basis = basis_text.get(
        risk_basis,
        "security indicators were detected"
    )

    explanation = (
        f"QRShield classified this destination as {risk} "
        f"because {explanation_basis}."
    )

    if correlation_count >= 2:
        explanation += (
            " Multiple security indicators reinforce this assessment."
        )

    return explanation

def build_risk_evidence_explanation(risk_analysis):
    """
    Explain the evidence supporting the QRShield risk assessment.
    """

    if not isinstance(risk_analysis, dict):
        return "Risk evidence is unavailable."

    risk = risk_analysis.get("risk", "UNKNOWN")
    risk_basis = risk_analysis.get(
        "risk_basis",
        "Unknown"
    )

    evidence = risk_analysis.get(
        "evidence",
        {}
    )

    high_count = evidence.get("high", 0)
    medium_count = evidence.get("medium", 0)
    low_count = evidence.get("low", 0)

    correlation = risk_analysis.get(
        "correlation",
        {}
    )

    correlation_count = correlation.get(
        "count",
        0
    )

    correlation_level = correlation.get(
        "level",
        "NONE"
    )

    finding_parts = []

    if high_count:
        finding_parts.append(
            f"{high_count} high-severity finding"
            + ("s" if high_count != 1 else "")
        )

    if medium_count:
        finding_parts.append(
            f"{medium_count} medium-severity finding"
            + ("s" if medium_count != 1 else "")
        )

    if low_count:
        finding_parts.append(
            f"{low_count} low-severity finding"
            + ("s" if low_count != 1 else "")
        )

    if finding_parts:
        evidence_text = ", ".join(finding_parts)
    else:
        evidence_text = "no individual security findings"

    if correlation_count > 0:
        correlation_text = (
            f"{correlation_count} correlated security signal"
            + ("s" if correlation_count != 1 else "")
            + f" classified at {correlation_level} correlation"
        )
    else:
        correlation_text = "no correlated security signals"

    return (
        f"Risk level: {risk}. "
        f"Primary basis: {risk_basis}. "
        f"Evidence: {evidence_text}. "
        f"Correlation: {correlation_text}."
    )

def validate_explainability(result):
    """
    Validate that QRShield produced a complete explainability result.
    """

    if not isinstance(result, dict):
        return {
            "valid": False,
            "missing": ["result"]
        }

    required_fields = [
        "score",
        "risk",
        "findings",
        "explanations",
        "overall_explanation",
        "risk_evidence_explanation",
        "risk_analysis"
    ]

    missing = [
        field
        for field in required_fields
        if field not in result
    ]

    if missing:
        return {
            "valid": False,
            "missing": missing
        }

    risk_analysis = result.get("risk_analysis")

    if not isinstance(risk_analysis, dict):
        return {
            "valid": False,
            "missing": ["risk_analysis"]
        }

    required_risk_fields = [
        "score",
        "risk",
        "risk_basis",
        "confidence",
        "evidence",
        "correlation"
    ]

    missing_risk_fields = [
        field
        for field in required_risk_fields
        if field not in risk_analysis
    ]

    if missing_risk_fields:
        return {
            "valid": False,
            "missing": missing_risk_fields
        }

    if result["score"] != risk_analysis["score"]:
        return {
            "valid": False,
            "missing": ["score_consistency"]
        }

    if result["risk"] != risk_analysis["risk"]:
        return {
            "valid": False,
            "missing": ["risk_consistency"]
        }

    return {
        "valid": True,
        "missing": []
    }

def analyze_reputation(url, hostname=None):
    """
    Analyze URL reputation using multiple threat-intelligence providers.
    """

    if not url:
        return {
            "status": "NO_URL",
            "reputation": "UNKNOWN",
            "sources": [],
            "findings": []
        }

    urlhaus_result = query_urlhaus(url)
    google_result = query_google_safe_browsing(url)

    sources = [
        urlhaus_result,
        google_result
    ]

    consensus = evaluate_reputation_consensus(sources)

    findings = []

    threat_found = any(
        source.get("status") == "FOUND"
        for source in sources
    )

    if threat_found:

        reputation = "MALICIOUS"
        status = "THREAT_FOUND"

        for source in sources:
            if source.get("status") == "FOUND":
                findings.append({
                    "severity": "high",
                    "source": source["source"],
                    "message": (
                        "URL was found in this "
                        "threat-intelligence database."
                    )
                })

    elif all(
        source.get("status") == "NOT_FOUND"
        for source in sources
    ):

        reputation = "UNKNOWN"
        status = "NO_MATCH"

    else:

        reputation = "UNKNOWN"
        status = "INTELLIGENCE_UNAVAILABLE"

    return {
        "status": status,
        "reputation": reputation,
        "sources": sources,
        "findings": findings,
        "consensus": consensus
    }

def evaluate_reputation_risk(reputation_analysis):
    """
    Evaluate risk contribution from reputation intelligence.
    """

    if not reputation_analysis:
        return {
            "score": 0,
            "findings": []
        }

    score = 0
    findings = []

    if reputation_analysis.get("reputation") == "MALICIOUS":

        score += 30

        findings.append({
            "severity": "high",
            "source": "URLhaus",
            "message": (
                "URL was identified as malicious by external "
                "threat intelligence."
            )
        })

    return {
        "score": score,
        "findings": findings
    }

def detect_qr_content_type(content):
    """
    Identify the basic type of data decoded from a QR code.
    """

    if not content:
        return "EMPTY"

    content = content.strip()

    if content.lower().startswith(("http://", "https://")):
        return "URL"

    if content.upper().startswith("WIFI:"):
        return "WIFI"

    if content.upper().startswith("BEGIN:VCARD"):
        return "VCARD"

    if content.lower().startswith("mailto:"):
        return "EMAIL"

    if content.lower().startswith("tel:"):
        return "PHONE"

    if content.lower().startswith("sms:"):
        return "SMS"

    if content.lower().startswith("geo:"):
        return "GEOLOCATION"

    return "TEXT"

def analyze_wifi_qr(content):
    """
    Extract basic security information from a Wi-Fi QR payload.
    """

    if not content or not content.upper().startswith("WIFI:"):
        return {
            "valid": False,
            "authentication": None,
            "ssid": None,
            "hidden": False,
            "open_network": False,
            "finding": None
        }

    data = content[5:].rstrip(";")
    fields = {}

    for item in data.split(";"):
        if ":" not in item:
            continue

        key, value = item.split(":", 1)
        fields[key.upper()] = value

    authentication = fields.get("T", "").upper()
    ssid = fields.get("S")
    hidden = fields.get("H", "").lower() == "true"

    open_network = authentication in ("", "NOPASS")

    finding = None

    if open_network:
        finding = (
            "Wi-Fi QR code describes an open network "
            "without password-based authentication."
        )

    return {
        "valid": True,
        "authentication": authentication or "UNKNOWN",
        "ssid": ssid,
        "hidden": hidden,
        "open_network": open_network,
        "finding": finding
    }

def analyze_url(url):
    """
    Analyze a URL using explainable heuristic indicators.
    """

    score = 0
    findings = []
    features = []

    original_url = url.strip()
    content_type = detect_qr_content_type(url)

    wifi_analysis = None

    if content_type == "WIFI":
        wifi_analysis = analyze_wifi_qr(url)

    if content_type != "URL":
        return {
            "url": url,
            "content_type": content_type,
            "wifi_analysis": wifi_analysis,
            "score": 0,
            "risk": "LOW RISK",
            "risk_analysis": {
                "score": 0,
                "risk": "LOW RISK",
                "risk_basis": "Non-URL QR content",
                "confidence": "LOW",
                "evidence": {
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "reputation_confirmed": False,
                "signals": {},
                "correlation": {
                    "level": "NONE",
                    "count": 0,
                    "signals": []
                }
            },
            "findings": [],
            "explanations": [],
            "overall_explanation": (
                f"QRShield detected {content_type} content. "
                "URL security analysis was not applied."
            ),
            "risk_evidence_explanation": (
                "No URL security indicators were evaluated because "
                "the QR content is not a URL."
            ),
            "features": {}
        }
    
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

    redirect_chain = None
    redirect_analysis = None
    redirect_risk = None

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

    # STAGE 4 / TLS INTELLIGENCE
    tls_features = None

    if parsed.scheme == "https":
        tls_port = port_analysis["port"] or 443

        tls_result = get_tls_certificate(
            hostname,
            tls_port
        )

        if tls_result["retrieved"]:
            certificate_metadata = extract_certificate_metadata(
                tls_result["certificate"]
            )

            validity_analysis = analyze_certificate_validity(
                certificate_metadata["valid_from"],
                certificate_metadata["valid_until"]
            )

            identity_analysis = analyze_certificate_identity(
                hostname,
                certificate_metadata
            )

        else:
            certificate_metadata = extract_certificate_metadata(None)

            validity_analysis = analyze_certificate_validity(
                None,
                None
            )

            identity_analysis = analyze_certificate_identity(
                hostname,
                certificate_metadata
            )

        tls_features = build_tls_features(
            certificate_metadata,
            validity_analysis,
            identity_analysis
        )

        tls_risk = evaluate_tls_risk(tls_features)

        score += tls_risk["score"]

        for finding in tls_risk["findings"]:
            findings.append(finding)

        if tls_features is not None:
            features.append({
                "name": "TLS Intelligence",
                "value": tls_features
            })

    # Redirect Intelligence

    redirect_chain = follow_redirect_chain(
        normalized_url,
        max_redirects=5,
        timeout=5
    )

    redirect_analysis = analyze_redirect_chain(
        redirect_chain
    )

    redirect_classification = classify_redirect_chain(
    redirect_analysis
    )

    redirect_risk = evaluate_redirect_risk(
        redirect_analysis
    )

    score += redirect_risk["score"]
    findings.extend(redirect_risk["findings"])

    features.append({
        "name": "Redirect Intelligence",
        "redirect_count": redirect_analysis["redirect_count"],
        "classification": redirect_classification,
        "domains": redirect_analysis["domains"],
        "cross_domain_redirect": redirect_analysis[
            "cross_domain_redirect"
        ],
        "https_downgrade": redirect_analysis[
            "https_downgrade"
        ],
        "final_domain": redirect_analysis[
            "final_domain"
        ],
        "completed": redirect_chain.get(
            "completed",
            False
        ),
        "loop_detected": redirect_chain.get(
            "loop_detected",
            False
        ),
        "max_redirects_reached": redirect_chain.get(
            "max_redirects_reached",
            False
        ),
        "error": redirect_chain.get("error")
    })

    reputation_analysis = analyze_reputation(normalized_url, hostname)

    reputation_risk = evaluate_reputation_risk(
    reputation_analysis
    )

    score += reputation_risk["score"]
    findings.extend(reputation_risk["findings"])

    features.append({
    "name": "Reputation Intelligence",
    "status": reputation_analysis["status"],
    "reputation": reputation_analysis["reputation"],
    "consensus": reputation_analysis["consensus"],
    "sources": reputation_analysis["sources"],
    "findings": reputation_analysis["findings"]
    })

    

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

    risk_analysis = evaluate_risk_engine(
        score=score,
        findings=findings,
        reputation_analysis=reputation_analysis,
        dns_analysis=dns_analysis,
        tls_features=tls_features,
        redirect_analysis=redirect_analysis
    )

    overall_explanation = build_overall_explanation(
    risk_analysis
    )

    risk_evidence_explanation = build_risk_evidence_explanation(
    risk_analysis
    )


    explanations = [
    build_finding_explanation(finding)
    for finding in findings
    ]
    
    score = risk_analysis["score"]
    risk = risk_analysis["risk"]

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
        "content_type": content_type,
        "wifi_analysis": wifi_analysis,
        "score": score,
        "risk": risk,
        "risk_analysis": risk_analysis,
        "explanations": explanations,
        "overall_explanation": overall_explanation,
        "risk_evidence_explanation": risk_evidence_explanation,
        "findings": findings,
        "features": features
    }