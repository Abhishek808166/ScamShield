from flask import Flask, render_template, request, jsonify
from detector import analyze_message
from ai_analyzer import analyze_with_ai

app = Flask(__name__)


def calculate_ai_score(ai_result):
    """
    Convert the AI assessment into a numerical score.
    AI confidence affects how strongly its assessment contributes.
    """

    if not ai_result:
        return 0

    risk_scores = {
        "HIGH RISK": 90,
        "MEDIUM RISK": 60,
        "LOW RISK": 30,
        "LIKELY SAFE": 5
    }

    risk_level = ai_result.get("risk_level", "LIKELY SAFE")
    confidence = ai_result.get("confidence", 50)

    base_score = risk_scores.get(risk_level, 5)

    # Confidence adjusts the AI contribution.
    confidence_factor = confidence / 100

    return round(base_score * confidence_factor)


def calculate_final_score(rule_score, url_score, ai_score):
    """
    Combine all ScamShield intelligence layers.

    Rule detection: 60%
    URL intelligence: 20%
    AI assessment: 20%
    """

    final_score = (
        (rule_score * 0.60)
        + (url_score * 0.20)
        + (ai_score * 0.20)
    )

    return round(min(final_score, 100))


def get_risk_level(score):
    if score >= 70:
        return "HIGH RISK"
    elif score >= 40:
        return "MEDIUM RISK"
    elif score > 0:
        return "LOW RISK"
    else:
        return "LIKELY SAFE"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    message = data.get("message", "").strip()

    if not message:
        return jsonify({
            "error": "Please enter a message to analyze."
        }), 400

    # ==========================================
    # 1. RULE-BASED ANALYSIS
    # ==========================================

    result = analyze_message(message)

    rule_score = result["score"]


    # ==========================================
    # 2. URL INTELLIGENCE
    # ==========================================

    url_scores = [
        url["risk_score"]
        for url in result.get("url_analysis", [])
    ]

    if url_scores:
        url_score = max(url_scores)
    else:
        url_score = 0


    # ==========================================
    # 3. AI ANALYSIS
    # ==========================================

    ai_result = analyze_with_ai(message)

    ai_score = calculate_ai_score(ai_result)


    # ==========================================
    # 4. FINAL COMBINED SCORE
    # ==========================================

    final_score = calculate_final_score(
        rule_score,
        url_score,
        ai_score
    )

    final_risk_level = get_risk_level(final_score)


    # ==========================================
    # 5. RETURN EVERYTHING
    # ==========================================

    result["rule_score"] = rule_score
    result["url_score"] = url_score
    result["ai_score"] = ai_score

    result["score"] = final_score
    result["risk_level"] = final_risk_level

    result["ai_analysis"] = ai_result

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5001)