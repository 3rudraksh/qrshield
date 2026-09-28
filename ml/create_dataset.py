import csv
import random

from analyzer import analyze_url


SAFE_URLS = [
    "https://example.com",
    "https://example.org",
    "https://www.python.org",
    "https://www.wikipedia.org",
    "https://www.mozilla.org",
    "https://github.com",
    "https://www.microsoft.com",
    "https://www.google.com"
]


SUSPICIOUS_URLS = [
    "http://192.168.1.10/login",
    "http://example.com/verify/account/password",
    "http://example.com/login?redirect=http://evil.example",
    "http://secure-account-login.example.com/verify",
    "http://example.com/update/security/confirm/password",
    "http://example.com/login.php?user=admin&verify=1",
    "http://xn--pple-43d.example/login",
    "http://example.com/account/verify/password/reset"
]


FEATURES = [
    "URL Length",
    "Hostname Length",
    "Subdomain Count",
    "Path Depth",
    "Query Parameters",
    "Percent Encoded Characters",
    "Hostname Hyphens",
    "Hostname Digits",
    "Hostname Entropy"
]


def feature_map(features):

    return {
        feature.get("name"): feature.get("value")
        for feature in features
        if isinstance(feature, dict)
    }


def extract_features(result):

    features = feature_map(
        result.get("features", [])
    )

    return [
        features.get("URL Length", 0),
        features.get("Hostname Length", 0),
        features.get("Subdomain Count", 0),
        features.get("Path Depth", 0),
        features.get("Query Parameters", 0),
        features.get("Percent Encoded Characters", 0),
        features.get("Hostname Hyphens", 0),
        features.get("Hostname Digits", 0),
        features.get("Hostname Entropy", 0)
    ]


def generate_dataset():

    rows = []

    for url in SAFE_URLS:

        result = analyze_url(url)

        rows.append(
            extract_features(result) + [0]
        )

    for url in SUSPICIOUS_URLS:

        result = analyze_url(url)

        rows.append(
            extract_features(result) + [1]
        )

    random.shuffle(rows)

    with open(
        "ml/dataset.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow(
            FEATURES + ["label"]
        )

        writer.writerows(rows)


if __name__ == "__main__":

    generate_dataset()

    print(
        "Dataset created: ml/dataset.csv"
    )