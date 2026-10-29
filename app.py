
from flask import Flask, render_template, request

app = Flask(__name__)

SCAM_RULES = {
    "Payment Request": [
        "registration fee",
        "processing fee",
        "pay now",
        "pay to secure",
        "advance payment",
        "refundable fee",
    ],
    "Urgency and Pressure": [
        "act immediately",
        "limited time",
        "urgent",
        "within 24 hours",
        "immediately",
    ],
    "Prize and Reward": [
        "you have won",
        "claim your prize",
        "lottery winner",
        "free gift",
        "congratulations",
    ],
    "Suspicious Recruitment": [
        "guaranteed job",
        "no interview required",
        "job confirmed",
        "pay for training",
        "100% placement",
    ],
    "Sensitive Information": [
        "share your otp",
        "send your password",
        "bank details",
        "card number",
        "click this link",
    ],
}


def analyze_message(message):
    text = message.lower()
    findings = []

    for category, phrases in SCAM_RULES.items():
        for phrase in phrases:
            if phrase in text:
                findings.append({
                    "category": category,
                    "phrase": phrase,
                })

    score = min(len(findings) * 20, 100)

    if score >= 60:
        risk = "High"
    elif score >= 20:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "score": score,
        "risk": risk,
        "findings": findings,
    }


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    message = ""

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        if message:
            result = analyze_message(message)

    return render_template(
        "index.html",
        result=result,
        message=message,
    )


if __name__ == "__main__":
    app.run(debug=True)

