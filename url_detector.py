import re
from urllib.parse import urlparse
from db import get_db_connection


def analyze_url(url):

    suspicious_patterns = {
        "http://": 2,
        "bit.ly": 1,
        "tinyurl.com": 1,
        "t.co": 1,
        "is.gd": 3,
        "login": 1,
        "verify": 1,
        "account": 1,
        "password": 2,
        "secure": 0
    }

    tracking_parameters = [
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "fbclid",
        "gclid"
    ]

    redirect_parameters = [
        "redirect",
        "redirect_url",
        "return=",
        "next=",
        "url="
    ]

    url_lower = url.lower()

    found_patterns = []
    reasons = []
    risk_score = 0

    # 1. Tracking parameters
    for parameter in tracking_parameters:

        if parameter in url_lower:

            found_patterns.append("Tracking parameter")

            reasons.append(
                f"URL contains tracking parameter: {parameter}"
            )

            risk_score += 0

    # 2. Redirect parameters
    for parameter in redirect_parameters:

        if parameter in url_lower:

            found_patterns.append("Redirect parameter")

            reasons.append(
                f"URL contains redirect parameter: {parameter}"
            )

            risk_score += 2

    # 3. IP address detection
    if re.search(
        r"https?://\d{1,3}(\.\d{1,3}){3}",
        url_lower
    ):

        found_patterns.append("IP address")

        reasons.append(
            "URL uses an IP address instead of a domain name"
        )

        risk_score += 3

    # 4. Parse hostname
    parsed_url = urlparse(url)

    hostname = parsed_url.hostname

    if hostname:

        hostname = hostname.lower()

               # 5. Known threat database check
    if hostname:

        connection = get_db_connection()

        threat = None

        for domain, threat_type, threat_score, description in connection.execute(
            """
            SELECT domain, threat_type, risk_score, description
            FROM url_threats
            """
        ):

            if hostname == domain or hostname.endswith("." + domain):

                threat = (
                    threat_type,
                    threat_score,
                    description
                )

                break

        connection.close()

        if threat:

            threat_type, threat_score, description = threat

            found_patterns.append(threat_type)

            reasons.append(
                f"{description}: {hostname}"
            )

            risk_score += threat_score

        # 6. Many subdomains
        domain_parts = hostname.split(".")

        if len(domain_parts) >= 4:

            found_patterns.append("Many subdomains")

            reasons.append(
                "URL contains an unusually large number of subdomains"
            )

            risk_score += 2

    # 7. @ character
    if "@" in url:

        found_patterns.append("@")

        reasons.append(
            "URL contains @ which can be used to disguise the destination"
        )

        risk_score += 3

    # 8. URL encoding
    if re.search(r"%[0-9a-fA-F]{2}", url):

        found_patterns.append("URL encoding")

        reasons.append(
            "URL contains encoded characters that may hide its actual content"
        )

        risk_score += 1

    # 9. Suspicious keywords
    for pattern, score in suspicious_patterns.items():

        if pattern in url_lower:

            found_patterns.append(pattern)

            reasons.append(
                f"Contains suspicious pattern: {pattern}"
            )

            risk_score += score

    # 10. Calculate risk level
    if risk_score >= 6:

        risk_level = "High Risk"

    elif risk_score >= 3:

        risk_level = "Medium Risk"

    else:

        risk_level = "Low Risk"

    # 11. Return results
    return found_patterns, risk_score, risk_level, reasons


# Test
if __name__ == "__main__":

    test_url = "https://snifferip.com/2grX6.mp4"

    patterns, score, level, reasons = analyze_url(test_url)

    print("Suspicious patterns:", patterns)
    print("Risk score:", score)
    print("Risk level:", level)

    print("Reasons:")

    for reason in reasons:

        print("-", reason)