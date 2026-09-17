document.addEventListener("DOMContentLoaded", function () {

    // =========================================================
    // ELEMENTS
    // =========================================================

    const textarea = document.getElementById("messageInput");
    const button = document.getElementById("analyzeButton");
    const result = document.getElementById("result");

    const HISTORY_KEY = "scamshield_scan_history";
    const MAX_HISTORY = 50;


    // =========================================================
    // HISTORY
    // =========================================================

    function getHistory() {

        try {
            return JSON.parse(
                localStorage.getItem(HISTORY_KEY)
            ) || [];
        } catch (error) {
            console.error("History error:", error);
            return [];
        }
    }


    function saveToHistory(data, message) {

        try {

            const history = getHistory();

            const scan = {
                message: message,
                score: data.score,
                risk_level: data.risk_level,
                timestamp: new Date().toISOString()
            };

            history.unshift(scan);

            if (history.length > MAX_HISTORY) {
                history.length = MAX_HISTORY;
            }

            localStorage.setItem(
                HISTORY_KEY,
                JSON.stringify(history)
            );

            renderDashboard();

        } catch (error) {
            console.error("Unable to save history:", error);
        }
    }


    function clearHistory() {

        localStorage.removeItem(HISTORY_KEY);

        renderDashboard();
    }


    function formatTime(timestamp) {

        try {

            const date = new Date(timestamp);

            return date.toLocaleString([], {
                day: "numeric",
                month: "short",
                hour: "numeric",
                minute: "2-digit"
            });

        } catch (error) {
            return "";
        }
    }


    function getShortMessage(message) {

        if (!message) {
            return "";
        }

        if (message.length > 80) {
            return message.substring(0, 80) + "...";
        }

        return message;
    }


    function getRiskClass(riskLevel) {

        if (!riskLevel) {
            return "safe";
        }

        const level = riskLevel.toUpperCase();

        if (level.includes("HIGH")) {
            return "high";
        }

        if (level.includes("MEDIUM")) {
            return "medium";
        }

        return "safe";
    }


    // =========================================================
    // DASHBOARD
    // =========================================================

    function renderDashboard() {

        const existingDashboard =
            document.getElementById("scamshieldDashboard");

        if (existingDashboard) {
            existingDashboard.remove();
        }

        const history = getHistory();

        const total = history.length;

        const high = history.filter(item =>
            item.risk_level &&
            item.risk_level.toUpperCase().includes("HIGH")
        ).length;

        const medium = history.filter(item =>
            item.risk_level &&
            item.risk_level.toUpperCase().includes("MEDIUM")
        ).length;

        const safe = history.filter(item =>
            !item.risk_level ||
            (
                !item.risk_level.toUpperCase().includes("HIGH") &&
                !item.risk_level.toUpperCase().includes("MEDIUM")
            )
        ).length;


        const dashboard = document.createElement("section");

        dashboard.id = "scamshieldDashboard";

        dashboard.innerHTML = `

            <div class="dashboard-heading">

                <div>

                    <p class="dashboard-label">
                        SECURITY DASHBOARD
                    </p>

                    <h2>
                        Scan Overview
                    </h2>

                </div>

                <button
                    type="button"
                    id="clearHistoryButton"
                    class="clear-history-button"
                >
                    Clear History
                </button>

            </div>


            <div class="dashboard-stats">

                <div class="dashboard-stat">

                    <span class="stat-label">
                        TOTAL SCANS
                    </span>

                    <strong>
                        ${total}
                    </strong>

                    <small>
                        Messages analyzed
                    </small>

                </div>


                <div class="dashboard-stat">

                    <span class="stat-label">
                        HIGH RISK
                    </span>

                    <strong>
                        ${high}
                    </strong>

                    <small>
                        Dangerous patterns
                    </small>

                </div>


                <div class="dashboard-stat">

                    <span class="stat-label">
                        MEDIUM RISK
                    </span>

                    <strong>
                        ${medium}
                    </strong>

                    <small>
                        Suspicious messages
                    </small>

                </div>


                <div class="dashboard-stat">

                    <span class="stat-label">
                        SAFE
                    </span>

                    <strong>
                        ${safe}
                    </strong>

                    <small>
                        Low-risk messages
                    </small>

                </div>

            </div>


            <div class="recent-scans">

                <div class="recent-header">

                    <div>

                        <p class="dashboard-label">
                            ACTIVITY
                        </p>

                        <h3>
                            Recent Scans
                        </h3>

                    </div>

                    <span>
                        ${total} recent
                    </span>

                </div>


                ${
                    history.length === 0
                    ?
                    `
                    <div class="no-history">
                        No scans yet. Analyze a message to begin.
                    </div>
                    `
                    :
                    history.slice(0, 5).map(item => {

                        const riskClass =
                            getRiskClass(item.risk_level);

                        return `

                            <div class="recent-scan">

                                <div class="recent-message">

                                    <span class="recent-risk ${riskClass}">
                                        ${item.risk_level || "LIKELY SAFE"}
                                    </span>

                                    <p>
                                        ${escapeHTML(
                                            getShortMessage(item.message)
                                        )}
                                    </p>

                                </div>


                                <div class="recent-score">

                                    <strong>
                                        ${item.score}/100
                                    </strong>

                                    <small>
                                        ${formatTime(item.timestamp)}
                                    </small>

                                </div>

                            </div>

                        `;

                    }).join("")
                }

            </div>

        `;


        const analyzerCard =
            document.querySelector(".analyzer-card");

        if (analyzerCard) {

            analyzerCard.insertAdjacentElement(
                "afterend",
                dashboard
            );

        }


        const clearButton =
            document.getElementById(
                "clearHistoryButton"
            );

        if (clearButton) {

            clearButton.addEventListener(
                "click",
                clearHistory
            );

        }

    }


    // =========================================================
    // HTML ESCAPE
    // =========================================================

    function escapeHTML(value) {

        if (value === null || value === undefined) {
            return "";
        }

        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }


    // =========================================================
    // RISK DESCRIPTION
    // =========================================================

    function getRiskDescription(score) {

        if (score >= 70) {

            return `
                This message contains multiple indicators commonly
                associated with scams, phishing or social engineering.
                Avoid clicking links or sharing sensitive information.
            `;

        }

        if (score >= 40) {

            return `
                This message contains several suspicious characteristics.
                Verify the sender and request through an independent
                official channel before taking action.
            `;

        }

        if (score > 0) {

            return `
                Some potentially suspicious patterns were detected.
                Remain cautious and verify the message before responding.
            `;

        }

        return `
            No major scam indicators were detected in this message.
            However, always verify unexpected requests independently.
        `;
    }


    // =========================================================
    // WARNING HTML
    // =========================================================

    function buildDetectedHTML(detected) {

        if (!detected || detected.length === 0) {

            return `
                <div class="safe-message">
                    ✓ No major scam indicators detected.
                </div>
            `;

        }


        let html = "";


        detected.forEach(item => {

            const matches = item.matches
                ? item.matches.join(", ")
                : "";

            const reason = item.reason
                ? item.reason
                : "This message contains a potentially suspicious pattern.";


            html += `

                <div class="warning-item">

                    <div class="warning-header">

                        <strong>
                            ⚠ ${escapeHTML(item.category)}
                        </strong>

                        <span class="warning-matches">
                            ${escapeHTML(matches)}
                        </span>

                    </div>


                    <p>
                        ${escapeHTML(reason)}
                    </p>

                </div>

            `;

        });


        return html;
    }


    // =========================================================
    // URL INTELLIGENCE
    // =========================================================

    function buildURLHTML(urlAnalysis) {

        if (!urlAnalysis || urlAnalysis.length === 0) {

            return "";

        }


        let html = `

            <div class="url-intelligence">

                <div class="url-section-header">

                    <div>

                        <p class="url-label">
                            🔗 URL INTELLIGENCE
                        </p>

                        <h3>
                            Link Analysis
                        </h3>

                    </div>

                    <span>
                        ${urlAnalysis.length}
                        URL${urlAnalysis.length === 1 ? "" : "s"}
                    </span>

                </div>

        `;


        urlAnalysis.forEach(url => {

            const riskClass =
                url.risk_level === "HIGH"
                    ? "high"
                    : url.risk_level === "MEDIUM"
                        ? "medium"
                        : "low";


            html += `

                <div class="url-analysis-item">

                    <div class="url-analysis-top">

                        <div class="url-value">
                            ${escapeHTML(url.url)}
                        </div>

                        <div class="url-risk ${riskClass}">
                            ${escapeHTML(url.risk_level)}
                            ·
                            ${url.risk_score}/100
                        </div>

                    </div>


                    ${
                        url.indicators &&
                        url.indicators.length > 0
                        ?
                        `
                        <div class="url-indicators">

                            ${url.indicators.map(indicator => `
                                <div class="url-indicator">
                                    ⚠ ${escapeHTML(indicator)}
                                </div>
                            `).join("")}

                        </div>
                        `
                        :
                        `
                        <div class="url-safe">
                            ✓ No major URL indicators detected.
                        </div>
                        `
                    }

                </div>

            `;

        });


        html += `</div>`;

        return html;
    }


    // =========================================================
    // AI SECURITY ASSESSMENT
    // =========================================================

    function buildAIHTML(ai) {

        if (!ai) {
            return "";
        }


        return `

            <div class="ai-security-card">

                <div class="ai-security-header">

                    <div>

                        <p class="ai-label">
                            AI SECURITY ASSESSMENT
                        </p>

                        <h3>
                            AI-Powered Analysis
                        </h3>

                    </div>


                    <div class="ai-risk-badge">
                        ${escapeHTML(
                            ai.risk_level || "UNKNOWN"
                        )}
                    </div>

                </div>


                <div class="ai-confidence">

                    <span>
                        Confidence
                    </span>

                    <strong>
                        ${Number(ai.confidence) || 0}%
                    </strong>

                </div>


                <div class="ai-detail">

                    <span class="ai-detail-label">
                        Intent
                    </span>

                    <p>
                        ${escapeHTML(
                            ai.intent || "Not determined"
                        )}
                    </p>

                </div>


                <div class="ai-detail">

                    <span class="ai-detail-label">
                        Explanation
                    </span>

                    <p>
                        ${escapeHTML(
                            ai.explanation ||
                            "No additional explanation available."
                        )}
                    </p>

                </div>


                <div class="ai-recommendation">

                    <span class="ai-detail-label">
                        Safety Recommendation
                    </span>

                    <p>
                        ${escapeHTML(
                            ai.recommendation ||
                            "Verify the message through official channels."
                        )}
                    </p>

                </div>

            </div>

        `;
    }


    // =========================================================
    // INTELLIGENCE BREAKDOWN
    // =========================================================

    function buildBreakdownHTML(data) {

        return `

            <div class="intelligence-breakdown">

                <div class="breakdown-header">

                    <p class="breakdown-label">
                        INTELLIGENCE BREAKDOWN
                    </p>

                    <span>
                        Combined Risk Analysis
                    </span>

                </div>


                <div class="breakdown-grid">


                    <div class="breakdown-item">

                        <div class="breakdown-top">

                            <span>
                                Rule Detection
                            </span>

                            <strong>
                                ${data.rule_score || 0}/100
                            </strong>

                        </div>


                        <div class="breakdown-bar">

                            <div
                                class="breakdown-fill"
                                style="width: ${Math.min(
                                    data.rule_score || 0,
                                    100
                                )}%"
                            ></div>

                        </div>


                        <small>
                            60% weight
                        </small>

                    </div>


                    <div class="breakdown-item">

                        <div class="breakdown-top">

                            <span>
                                URL Intelligence
                            </span>

                            <strong>
                                ${data.url_score || 0}/100
                            </strong>

                        </div>


                        <div class="breakdown-bar">

                            <div
                                class="breakdown-fill"
                                style="width: ${Math.min(
                                    data.url_score || 0,
                                    100
                                )}%"
                            ></div>

                        </div>


                        <small>
                            20% weight
                        </small>

                    </div>


                    <div class="breakdown-item">

                        <div class="breakdown-top">

                            <span>
                                AI Assessment
                            </span>

                            <strong>
                                ${data.ai_score || 0}/100
                            </strong>

                        </div>


                        <div class="breakdown-bar">

                            <div
                                class="breakdown-fill"
                                style="width: ${Math.min(
                                    data.ai_score || 0,
                                    100
                                )}%"
                            ></div>

                        </div>


                        <small>
                            20% weight
                        </small>

                    </div>


                </div>

            </div>

        `;
    }


    // =========================================================
    // RENDER RESULT
    // =========================================================

    function renderResult(data) {

        const riskDescription =
            getRiskDescription(data.score);


        const detectedHTML =
            buildDetectedHTML(data.detected);


        const breakdownHTML =
            buildBreakdownHTML(data);


        const aiHTML =
            buildAIHTML(data.ai_analysis);


        const urlHTML =
            buildURLHTML(data.url_analysis);


        result.innerHTML = `

            <div class="risk-result">


                <!-- HEADER -->

                <div class="risk-header">

                    <div>

                        <p class="result-label">
                            SCAMSHIELD ANALYSIS
                        </p>

                        <h2>
                            ${escapeHTML(data.risk_level)}
                        </h2>

                    </div>


                    <div class="risk-score">

                        ${data.score}

                        <span>
                            /100
                        </span>

                    </div>

                </div>


                <!-- RISK BAR -->

                <div class="risk-bar">

                    <div
                        class="risk-fill"
                        style="width: ${Math.min(
                            data.score,
                            100
                        )}%"
                    ></div>

                </div>


                <!-- DESCRIPTION -->

                <p class="result-description">

                    ScamShield detected

                    <strong>
                        ${data.detected
                            ? data.detected.length
                            : 0}
                    </strong>

                    potential warning sign(s)
                    in this message.

                </p>


                <!-- ASSESSMENT -->

                <div class="risk-explanation">

                    <strong>
                        Assessment:
                    </strong>

                    ${riskDescription}

                </div>


                <!-- WARNINGS -->

                <div class="warnings">

                    ${detectedHTML}

                </div>


                <!-- BREAKDOWN -->

                ${breakdownHTML}


                <!-- AI -->

                ${aiHTML}


                <!-- URL -->

                ${urlHTML}


                <!-- SAFETY TIP -->

                <div class="safety-tip">

                    <strong>
                        🛡️ Safety Tip
                    </strong>

                    <p>
                        Never share OTPs, passwords, PINs or banking
                        credentials in response to unexpected messages.
                        Verify requests using official channels.
                    </p>

                </div>


            </div>

        `;


        result.style.display = "block";


        // Smoothly bring result into view

        setTimeout(() => {

            result.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        }, 100);

    }


    // =========================================================
    // SCANNING STATE
    // =========================================================

    function startScanningAnimation() {

        const scanningMessages = [

            "🔍 Checking threat patterns...",

            "🔗 Analyzing URLs...",

            "🤖 Running AI assessment...",

            "🛡️ Calculating final risk..."

        ];


        let scanStep = 0;


        button.disabled = true;

        button.textContent =
            scanningMessages[scanStep];


        const interval = setInterval(() => {

            scanStep++;

            if (
                scanStep >=
                scanningMessages.length
            ) {

                scanStep = 0;

            }


            button.textContent =
                scanningMessages[scanStep];

        }, 900);


        return interval;
    }


    // =========================================================
    // ANALYZE MESSAGE
    // =========================================================

    button.addEventListener(
        "click",
        async function () {

            const message =
                textarea.value.trim();


            // Empty message

            if (!message) {

                result.innerHTML = `

                    <div class="result-error">

                        Please enter a message to analyze.

                    </div>

                `;

                result.style.display = "block";

                textarea.focus();

                return;

            }


            // Start scanning animation

            const scanAnimation =
                startScanningAnimation();


            try {

                const response =
                    await fetch(
                        "/analyze",
                        {

                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body: JSON.stringify({
                                message: message
                            })

                        }
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    throw new Error(
                        data.error ||
                        "Analysis failed"
                    );

                }


                // Stop animation

                clearInterval(
                    scanAnimation
                );


                // Save scan

                saveToHistory(
                    data,
                    message
                );


                // Render result

                renderResult(data);


            } catch (error) {

                clearInterval(
                    scanAnimation
                );


                console.error(
                    "ScamShield error:",
                    error
                );


                result.innerHTML = `

                    <div class="result-error">

                        Unable to analyze the message.
                        Please try again.

                    </div>

                `;

                result.style.display = "block";

            } finally {

                button.disabled = false;

                button.textContent =
                    "Analyze Message →";

            }

        }
    );


    // =========================================================
    // DEMO EXAMPLE BUTTONS
    // =========================================================

    document
        .querySelectorAll(".example-button")
        .forEach(button => {

            button.addEventListener(
                "click",
                function () {

                    const message =
                        this.getAttribute(
                            "data-message"
                        );


                    if (!message) {
                        return;
                    }


                    textarea.value =
                        message;


                    textarea.focus();


                    textarea.scrollIntoView({
                        behavior: "smooth",
                        block: "center"
                    });

                }
            );

        });


    // =========================================================
    // INITIAL DASHBOARD
    // =========================================================

    renderDashboard();

});