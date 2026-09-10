from flask import Flask, render_template, request
from db import get_db_connection
from email_detector import analyze_email
from url_detector import analyze_url
app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/phone-checker", methods=["GET", "POST"])
def phone_checker():

    report = None

    if request.method == "POST":

        phone_number = request.form["phone_number"]

        connection = get_db_connection()

        report = connection.execute(
            "SELECT * FROM phone_reports WHERE phone_number = ?",
            (phone_number,)
        ).fetchone()

        connection.close()

    return render_template(
        "phone_checker.html",
        report=report
    )

@app.route("/report-number", methods=["GET", "POST"])
def report_number():

    message = None

    if request.method == "POST":

        phone_number = request.form["phone_number"]
        report_type = request.form["report_type"]
        description = request.form["description"]

        connection = get_db_connection()

        connection.execute(
            """
            INSERT INTO phone_reports
            (phone_number, report_type, description)
            VALUES (?, ?, ?)
            """,
            (phone_number, report_type, description)
        )

        connection.commit()
        connection.close()

        message = "Report submitted successfully!"

    return render_template(
        "report_number.html",
        message=message
    )

@app.route("/email-checker", methods=["GET", "POST"])
def email_checker():

    found_keywords = []
    risk_score = 0
    risk_level = None
    reasons = []

    if request.method == "POST":

        email_text = request.form["email_text"]

        found_keywords, risk_score, risk_level, reasons = analyze_email(email_text)

    return render_template(
        "email_checker.html",
        found_keywords=found_keywords,
        risk_score=risk_score,
        risk_level=risk_level,
        reasons=reasons
    )


@app.route("/url-checker", methods=["GET", "POST"])
def url_checker():

    patterns = []
    score = 0
    level = None
    reasons = []

    if request.method == "POST":

        url = request.form["url"]

        patterns, score, level, reasons = analyze_url(url)

    return render_template(
        "url_checker.html",
        found_patterns=patterns,
        risk_score=score,
        risk_level=level,
        reasons=reasons
    )

@app.route("/report-cybercrime")
def report_cybercrime():
    return render_template("report_cybercrime.html")

@app.route("/awareness")
def awareness():
    return render_template("awareness.html")

@app.route("/awareness/<topic>")
def awareness_detail(topic):

    threats = {
        "phishing": {
            "title": "Phishing",
            "icon": "🔐",
            "description": "Phishing is a cybercrime where attackers use fake messages, emails or websites to trick people into providing sensitive information.",
            "warning_signs": [
                "Unexpected messages asking for personal information",
                "Links leading to unfamiliar websites",
                "Urgent messages telling you to act immediately",
                "Requests for passwords, OTPs or banking information"
            ],
            "safety": [
                "Do not click suspicious links",
                "Check the sender and website address carefully",
                "Never share OTPs or passwords",
                "Use official websites or apps for important services"
            ]
        },

        "upi-fraud": {
            "title": "UPI Fraud",
            "icon": "💳",
            "description": "UPI fraud involves tricks such as fake payment requests, QR codes or social engineering to steal money from victims.",
            "warning_signs": [
                "Unknown people asking you to scan a QR code",
                "Unexpected collect/payment requests",
                "Someone asking for your UPI PIN",
                "Promises of refunds or rewards requiring a payment"
            ],
            "safety": [
                "Never share your UPI PIN",
                "Never enter your PIN to receive money",
                "Verify the receiver before making a payment",
                "Reject unexpected payment requests"
            ]
        },

        "otp-scam": {
            "title": "OTP Scam",
            "icon": "🔑",
            "description": "In an OTP scam, criminals try to convince victims to reveal one-time passwords or other authentication information.",
            "warning_signs": [
                "Someone asking you to tell them an OTP",
                "Unexpected OTP messages",
                "Calls claiming to be from banks or companies",
                "Pressure to share authentication information quickly"
            ],
            "safety": [
                "Never share an OTP with anyone",
                "Do not share banking passwords",
                "Contact your bank through its official number",
                "Be suspicious of unexpected authentication requests"
            ]
        },

        "fake-kyc": {
            "title": "Fake KYC",
            "icon": "📱",
            "description": "Fake KYC scams use messages or calls pretending to be from banks, financial services or companies and demand urgent KYC updates.",
            "warning_signs": [
                "Messages threatening account suspension",
                "Links asking you to update KYC",
                "Requests for banking details",
                "Unknown apps or websites asking for verification"
            ],
            "safety": [
                "Verify KYC requests through official channels",
                "Do not click unknown KYC links",
                "Never share OTPs or banking passwords",
                "Contact the organization directly if unsure"
            ]
        },

        "job-scam": {
            "title": "Job Scam",
            "icon": "💼",
            "description": "Job scams involve fake recruiters or companies that promise employment and then ask victims for money or sensitive information.",
            "warning_signs": [
                "Guaranteed jobs with unusually high salaries",
                "Requests for registration or interview fees",
                "Recruiters using unofficial email addresses",
                "Requests for sensitive documents too early"
            ],
            "safety": [
                "Research the company before applying",
                "Never pay money to get a job",
                "Verify recruiters and job offers",
                "Avoid sharing sensitive information unnecessarily"
            ]
        },

        "investment-scam": {
            "title": "Investment Scam",
            "icon": "📈",
            "description": "Investment scams use fake investment opportunities and unrealistic profit promises to convince victims to transfer money.",
            "warning_signs": [
                "Guaranteed or unrealistic returns",
                "Pressure to invest immediately",
                "Unknown trading or investment platforms",
                "Requests to transfer money to personal accounts"
            ],
            "safety": [
                "Research the investment platform",
                "Be cautious of guaranteed high returns",
                "Do not invest because of pressure from strangers",
                "Verify financial services through official sources"
            ]
        }
    }

    threat = threats.get(topic)

    if threat is None:
        return "Threat not found", 404

    return render_template(
        "awareness_detail.html",
        threat=threat
    )


if __name__ == "__main__":
    app.run()