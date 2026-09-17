import os
import json
from dotenv import load_dotenv
from huggingface_hub import InferenceClient

load_dotenv()

hf_token = os.getenv("HF_TOKEN")

if not hf_token:
    raise ValueError("HF_TOKEN not found. Check your .env file.")

print("HF TOKEN FOUND:", hf_token.startswith("hf_"))

client = InferenceClient(
    api_key=hf_token,
    provider="auto"
)


def analyze_with_ai(message):
    try:
        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {
                    "role": "system",
                    "content": """
You are ScamShield, an AI cybersecurity message analyzer.

Analyze the user's message for potential:
- phishing
- financial scams
- credential theft
- impersonation
- social engineering
- fake rewards
- urgency or pressure
- threats
- suspicious requests

Do not claim that a message is definitely malicious.
Give a reasoned risk assessment based only on the message.

Return ONLY valid JSON.

Use exactly this structure:

{
    "risk_level": "HIGH RISK",
    "confidence": 90,
    "intent": "credential theft",
    "explanation": "Short explanation of the suspicious behavior.",
    "recommendation": "Short practical safety recommendation."
}

risk_level MUST be exactly one of:
HIGH RISK
MEDIUM RISK
LOW RISK
LIKELY SAFE

confidence MUST be an integer from 0 to 100.

Keep explanation and recommendation concise.
"""
                },
                {
                    "role": "user",
                    "content": message
                }
            ]
        )

        output = response.choices[0].message.content.strip()

        if output.startswith("```"):
            output = output.replace("```json", "")
            output = output.replace("```", "")
            output = output.strip()

        return json.loads(output)

    except Exception as error:
        print("AI analysis error:", error)
        return None


if __name__ == "__main__":

    test_message = """
    Your SBI account will be blocked today.
    Verify your account immediately and enter your OTP.
    """

    result = analyze_with_ai(test_message)

    print("\nSCAMSHIELD AI RESULT")
    print("====================")

    if result:
        print(json.dumps(result, indent=4))
    else:
        print("AI analysis failed.")