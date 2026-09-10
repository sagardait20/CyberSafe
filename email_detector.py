def analyze_email(text):

    suspicious_keywords = {
        "otp": 3,
        "password": 3,
        "account is blocked": 3,
        "verify": 2,
        "urgent": 2,
        "click": 1,
        "winner": 2,
        "prize": 2,
        "http://": 2,
        "bit.ly": 3,
        "tinyurl.com": 3,
        "click here": 2,
        "send money": 3,
        "bank account": 3,
        "credit card": 3,
        "refund": 2,
        "cash prize": 3,
        "claim your reward": 3
    }

    text_lower = text.lower()

    found_keywords = []
    reasons = []
    risk_score = 0

    for keyword, score in suspicious_keywords.items():

        if keyword in text_lower:
            found_keywords.append(keyword)
            reasons.append(f"Contains suspicious phrase: {keyword}")
            risk_score += score

    if risk_score >= 6:
        risk_level = "High Risk"
    elif risk_score >= 3:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    return found_keywords, risk_score, risk_level, reasons


if __name__ == "__main__":

    test_message = """
    Congratulations! You have won a cash prize.
    Claim your reward now.
    Click here: http://example.com
    Send money to receive your prize.
    """

    keywords, score, level, reasons = analyze_email(test_message)

    print("Suspicious keywords:", keywords)
    print("Risk score:", score)
    print("Risk level:", level)

    print("Reasons:")

    for reason in reasons:
        print("-", reason)