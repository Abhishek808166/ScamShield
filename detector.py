import re


# ============================================================
# SCAMSHIELD THREAT PATTERNS
# ============================================================

PATTERNS = {

    "Credential Request": {
        "keywords": [
            "otp",
            "password",
            "pin",
            "cvv",
            "verification code",
            "security code",
            "login details",
            "bank details",
            "account number",
            "card number",
            "atm pin",
            "upi pin",
        ],
        "weight": 25,
        "reason": (
            "The message asks for sensitive information such as "
            "an OTP, password, PIN or banking credentials."
        ),
    },


    "Financial Request": {
        "keywords": [
            "send money",
            "transfer money",
            "make payment",
            "pay now",
            "payment",
            "upi",
            "refund fee",
            "processing fee",
            "deposit",
            "wire transfer",
            "pay the fee",
            "send rs",
            "send ₹",
        ],
        "weight": 20,
        "reason": (
            "The message involves money, payments, fees or financial "
            "transactions that may be used to trick the recipient."
        ),
    },


    "Prize / Reward Scam": {
        "keywords": [
            "you won",
            "you have won",
            "winner",
            "lottery",
            "prize",
            "congratulations",
            "reward",
            "cash prize",
            "lucky winner",
            "cash reward",
            "claim your reward",
        ],
        "weight": 20,
        "reason": (
            "The message claims that the recipient has won a prize, "
            "reward or unexpected money."
        ),
    },


    "Urgency / Pressure": {
        "keywords": [
            "urgent",
            "immediately",
            "act now",
            "right now",
            "limited time",
            "within 24 hours",
            "expires today",
            "last chance",
            "do it now",
            "today only",
            "within an hour",
            "quickly",
        ],
        "weight": 15,
        "reason": (
            "The message creates pressure or urgency to make the "
            "recipient act before verifying the request."
        ),
    },


    "Threat / Account Warning": {
        "keywords": [
            "account will be blocked",
            "account will be suspended",
            "account suspended",
            "account blocked",
            "account will be closed",
            "legal action",
            "police action",
            "arrest",
            "fine",
            "penalty",
            "your account will be closed",
            "kyc failed",
            "kyc expired",
            "kyc update",
        ],
        "weight": 20,
        "reason": (
            "The message uses threats, account suspension or legal "
            "consequences to pressure the recipient."
        ),
    },


    "Suspicious Link": {
        "keywords": [
            "click here",
            "click the link",
            "click this link",
            "verify your account",
            "login here",
            "open this link",
            "visit this link",
            "click below",
            "tap here",
        ],
        "weight": 15,
        "reason": (
            "The message directs the recipient to click or open a "
            "link, which can be used for phishing."
        ),
    },


    "Impersonation": {
        "keywords": [
            "bank support",
            "customer care",
            "technical support",
            "government officer",
            "police officer",
            "income tax department",
            "customs officer",
            "account manager",
            "bank representative",
            "official representative",
            "customer service",
        ],
        "weight": 15,
        "reason": (
            "The message appears to present itself as a bank, "
            "government agency, support team or official representative."
        ),
    },
}


# ============================================================
# SUSPICIOUS URL PATTERNS
# ============================================================

SUSPICIOUS_DOMAINS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    "bit.ly",
    "tinyurl.com",
    "is.gd",
    "t.co",
    "goo.gl",
    "ow.ly",
]


# ============================================================
# COMBINATION RULES
# ============================================================

COMBINATIONS = [

    {
        "name": "Credential + Urgency",
        "categories": [
            "Credential Request",
            "Urgency / Pressure"
        ],
        "weight": 10,
        "reason": (
            "The message combines a request for sensitive credentials "
            "with pressure to act quickly."
        ),
    },

    {
        "name": "Credential + Threat",
        "categories": [
            "Credential Request",
            "Threat / Account Warning"
        ],
        "weight": 15,
        "reason": (
            "The message uses an account or legal threat while "
            "requesting sensitive credentials."
        ),
    },

    {
        "name": "Credential + Suspicious Link",
        "categories": [
            "Credential Request",
            "Suspicious Link"
        ],
        "weight": 15,
        "reason": (
            "The message combines a request for sensitive information "
            "with instructions to click or open a link."
        ),
    },

    {
        "name": "Prize + Financial Request",
        "categories": [
            "Prize / Reward Scam",
            "Financial Request"
        ],
        "weight": 20,
        "reason": (
            "The message combines a prize or reward claim with "
            "a request for money or payment."
        ),
    },

    {
        "name": "Prize + Urgency",
        "categories": [
            "Prize / Reward Scam",
            "Urgency / Pressure"
        ],
        "weight": 10,
        "reason": (
            "The message uses a prize or reward together with "
            "urgency to encourage immediate action."
        ),
    },

    {
        "name": "Threat + Urgency",
        "categories": [
            "Threat / Account Warning",
            "Urgency / Pressure"
        ],
        "weight": 10,
        "reason": (
            "The message combines an account or legal threat with "
            "pressure to act immediately."
        ),
    },

    {
        "name": "Impersonation + Credentials",
        "categories": [
            "Impersonation",
            "Credential Request"
        ],
        "weight": 15,
        "reason": (
            "The message appears to impersonate an organization "
            "while requesting sensitive information."
        ),
    },

    {
        "name": "Impersonation + Financial Request",
        "categories": [
            "Impersonation",
            "Financial Request"
        ],
        "weight": 15,
        "reason": (
            "The message appears to impersonate an official "
            "organization while requesting money or payment."
        ),
    },
]


# ============================================================
# KEYWORD DETECTION
# ============================================================

def find_keywords(message, keywords):

    matches = []

    for keyword in keywords:

        escaped = re.escape(keyword)

        pattern = (
            r"(?<!\w)"
            + escaped
            + r"(?!\w)"
        )

        if re.search(
            pattern,
            message,
            re.IGNORECASE
        ):
            matches.append(keyword)

    return matches


# ============================================================
# URL DETECTION
# ============================================================

def detect_urls(message):

    return re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        message,
        re.IGNORECASE
    )


# ============================================================
# INDIVIDUAL URL ANALYSIS
# ============================================================

def analyze_url(url):

    indicators = []

    risk_score = 0

    url_lower = url.lower()


    # HTTP instead of HTTPS
    if url_lower.startswith("http://"):

        indicators.append(
            "Uses HTTP instead of HTTPS"
        )

        risk_score += 15


    # Suspicious domains
    for domain in SUSPICIOUS_DOMAINS:

        if domain in url_lower:

            indicators.append(
                f"Suspicious or shortened domain pattern: {domain}"
            )

            risk_score += 30

            break


    # IP address instead of domain
    ip_pattern = (
        r"https?://(?:\d{1,3}\.){3}\d{1,3}"
    )

    if re.search(
        ip_pattern,
        url_lower
    ):

        indicators.append(
            "URL uses an IP address instead of a normal domain"
        )

        risk_score += 25


    # @ symbol
    if "@" in url:

        indicators.append(
            "URL contains an @ symbol"
        )

        risk_score += 20


    # Too many subdomains
    try:

        domain_part = re.sub(
            r"^https?://",
            "",
            url_lower
        ).split("/")[0]

        subdomain_count = domain_part.count(".")

        if subdomain_count >= 4:

            indicators.append(
                "URL contains an unusually large number of subdomains"
            )

            risk_score += 15

    except Exception:
        pass


    # Sensitive-action keywords
    suspicious_words = [
        "verify",
        "login",
        "secure",
        "account",
        "update",
        "payment",
        "bank",
        "wallet",
        "password",
        "otp",
    ]

    found_words = [
        word
        for word in suspicious_words
        if word in url_lower
    ]

    if found_words:

        indicators.append(
            "Sensitive-action keywords found: "
            + ", ".join(found_words)
        )

        risk_score += min(
            len(found_words) * 5,
            20
        )


    # Limit score
    risk_score = min(
        risk_score,
        100
    )


    # URL risk level
    if risk_score >= 60:

        risk_level = "HIGH"

    elif risk_score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    return {

        "url": url,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "indicators": indicators,
    }


# ============================================================
# SUSPICIOUS URL DETECTION
# ============================================================

def detect_suspicious_urls(urls):

    suspicious = []

    for url in urls:

        analysis = analyze_url(url)

        if analysis["risk_score"] >= 30:

            suspicious.append(url)

    return suspicious


# ============================================================
# MAIN MESSAGE ANALYZER
# ============================================================

def analyze_message(message):

    if not isinstance(message, str):

        message = str(message)


    message = message.strip()

    message_lower = message.lower()


    # Rule-based score
    score = 0

    detected = []

    detected_categories = set()


    # ========================================================
    # 1. THREAT PATTERN DETECTION
    # ========================================================

    for category, data in PATTERNS.items():

        matches = find_keywords(
            message_lower,
            data["keywords"]
        )

        if matches:

            detected_categories.add(category)

            score += data["weight"]

            detected.append({

                "category": category,

                "matches": matches,

                "weight": data["weight"],

                "reason": data["reason"],
            })


    # ========================================================
    # 2. URL DETECTION
    # ========================================================

    urls = detect_urls(message)

    suspicious_urls = detect_suspicious_urls(urls)


    # IMPORTANT:
    # URL risk is NOT added to the rule score.
    # URL Intelligence is handled separately by app.py.


    if suspicious_urls:

        detected_categories.add(
            "Suspicious Link"
        )

        existing_link = next(
            (
                item
                for item in detected
                if item["category"] == "Suspicious Link"
            ),
            None
        )


        if existing_link:

            existing_link["matches"].extend(
                suspicious_urls
            )

        else:

            detected.append({

                "category": "Suspicious Link",

                "matches": suspicious_urls,

                "weight": 0,

                "reason": (
                    "The message contains a URL with suspicious "
                    "characteristics. URL risk is calculated "
                    "separately by URL Intelligence."
                ),
            })


    # ========================================================
    # 3. COMBINATION DETECTION
    # ========================================================

    combination_count = 0


    for rule in COMBINATIONS:

        required_categories = set(
            rule["categories"]
        )


        if required_categories.issubset(
            detected_categories
        ):

            score += rule["weight"]

            combination_count += 1

            detected.append({

                "category": rule["name"],

                "matches": [
                    " + ".join(
                        rule["categories"]
                    )
                ],

                "weight": rule["weight"],

                "reason": rule["reason"],
            })


    # ========================================================
    # 4. BANKING CREDENTIAL RISK
    # ========================================================

    banking_terms = [
        "sbi",
        "hdfc",
        "icici",
        "axis bank",
        "bank account",
        "bank",
        "kyc",
    ]


    has_banking_context = any(
        term in message_lower
        for term in banking_terms
    )


    has_credentials = (
        "Credential Request"
        in detected_categories
    )


    if (
        has_banking_context
        and has_credentials
    ):

        score += 10

        detected.append({

            "category": "Banking Credential Risk",

            "matches": [
                "bank/kyc + credentials"
            ],

            "weight": 10,

            "reason": (
                "The message combines banking or KYC context "
                "with a request for sensitive credentials."
            ),
        })


    # ========================================================
    # 5. LIMIT RULE SCORE
    # ========================================================

    score = min(
        score,
        100
    )


    # ========================================================
    # 6. RULE-BASED RISK LEVEL
    # ========================================================

    if score >= 70:

        risk_level = "HIGH RISK"

    elif score >= 40:

        risk_level = "MEDIUM RISK"

    elif score > 0:

        risk_level = "LOW RISK"

    else:

        risk_level = "LIKELY SAFE"


    # ========================================================
    # 7. FINAL RESULT
    # ========================================================

    return {

        "score": score,

        "risk_level": risk_level,

        "detected": detected,

        "message_length": len(message),

        "url_count": len(urls),

        "suspicious_url_count": len(
            suspicious_urls
        ),

        "combination_count": combination_count,

        "url_analysis": [
            analyze_url(url)
            for url in urls
        ],
    }