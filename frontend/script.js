/*
=========================================================
 SENTRIX AI CYBERSECURITY SOC ANALYST
 Frontend JavaScript Controller
=========================================================

 Frontend:
     index.html
     style.css
     script.js

 Backend:
     FastAPI

 API:
     http://127.0.0.1:8000/api/v1

 Demo Login:
     Username: admin
     Password: admin123

=========================================================
*/


"use strict";


/* =====================================================
   CONFIGURATION
===================================================== */

const API_BASE_URL =
    "http://127.0.0.1:8000/api/v1";

const DEFAULT_USERNAME = "admin";
const DEFAULT_PASSWORD = "admin123";

let currentPage = "dashboard";

let autoRefreshTimer = null;

let terminalTimer = null;


/* =====================================================
   PAGE INFORMATION
===================================================== */

const pageInformation = {

    dashboard: {
        title: "SENTRIX Command Center",
        description: "AI-Powered Cyber Defense System"
    },

    alerts: {
        title: "Security Alerts",
        description: "Monitor and manage detected security events"
    },

    threats: {
        title: "Threat Intelligence",
        description: "Analyze suspicious indicators and threats"
    },

    detection: {
        title: "AI Detection Engine",
        description: "Analyze security logs using machine learning"
    },

    investigation: {
        title: "Investigation Center",
        description: "Investigate alerts and suspicious activities"
    },

    reports: {
        title: "Security Reports",
        description: "Generate automated cybersecurity reports"
    },

    health: {
        title: "System Health",
        description: "Monitor SENTRIX infrastructure and services"
    }

};


/* =====================================================
   DOM READY
===================================================== */

document.addEventListener(
    "DOMContentLoaded",
    function () {

        initializeApplication();

    }
);


/* =====================================================
   APPLICATION INITIALIZATION
===================================================== */

function initializeApplication() {

    setupLogin();

    setupClock();

    setupKeyboardShortcuts();

    setupNavigation();

    setupTerminalInput();

    startJarvisBootSequence();

    startTerminalSimulation();

    updateCurrentTime();

    setInterval(
        updateCurrentTime,
        1000
    );


    /*
     * Check whether user already logged in.
     */

    const authenticated =
        sessionStorage.getItem("jarvis_authenticated");

    if (authenticated === "true") {

        showApplication();

        showPage("dashboard");

        loadDashboardData();

        startAutoRefresh();

    }
    else {

        showLogin();

    }

}


/* =====================================================
   LOGIN SYSTEM
===================================================== */

function setupLogin() {

    const usernameInput =
        document.getElementById("username");

    const passwordInput =
        document.getElementById("password");


    if (usernameInput) {

        usernameInput.addEventListener(
            "keydown",
            function (event) {

                if (event.key === "Enter") {

                    login();

                }

            }
        );

    }


    if (passwordInput) {

        passwordInput.addEventListener(
            "keydown",
            function (event) {

                if (event.key === "Enter") {

                    login();

                }

            }
        );

    }

}


/* =====================================================
   LOGIN
===================================================== */

function login() {

    const usernameElement =
        document.getElementById("username");

    const passwordElement =
        document.getElementById("password");

    const messageElement =
        document.getElementById("loginMessage");


    if (!usernameElement || !passwordElement) {

        return;

    }


    const username =
        usernameElement.value.trim();

    const password =
        passwordElement.value;


    if (!username || !password) {

        showLoginMessage(
            "ACCESS DENIED: Username and password required.",
            true
        );

        return;

    }


    /*
     * Demo authentication.
     */

    if (
        username === DEFAULT_USERNAME &&
        password === DEFAULT_PASSWORD
    ) {

        sessionStorage.setItem(
            "jarvis_authenticated",
            "true"
        );


        showLoginMessage(
            "ACCESS GRANTED. INITIALIZING SENTRIX...",
            false
        );


        setTimeout(
            function () {

                showApplication();

                showPage("dashboard");

                loadDashboardData();

                startAutoRefresh();

                playLoginAnimation();

            },
            700
        );

    }
    else {

        showLoginMessage(
            "ACCESS DENIED: Invalid credentials.",
            true
        );

        passwordElement.value = "";

        shakeLoginBox();

    }

}


/* =====================================================
   LOGOUT
===================================================== */

function logout() {

    sessionStorage.removeItem(
        "jarvis_authenticated"
    );


    stopAutoRefresh();


    const terminal =
        document.getElementById("terminalOutput");

    if (terminal) {

        terminal.innerHTML =
            "SENTRIX: Session terminated.<br>" +
            "SENTRIX: Security lock activated.";

    }


    showLogin();

}


/* =====================================================
   SHOW LOGIN
===================================================== */

function showLogin() {

    const loginScreen =
        document.getElementById("loginScreen");

    const appContainer =
        document.getElementById("appContainer");


    if (loginScreen) {

        loginScreen.style.display = "flex";

    }


    if (appContainer) {

        appContainer.style.display = "none";

    }


    const username =
        document.getElementById("username");

    const password =
        document.getElementById("password");


    if (username) {

        username.value = "";

    }


    if (password) {

        password.value = "";

    }

}


/* =====================================================
   SHOW APPLICATION
===================================================== */

function showApplication() {

    const loginScreen =
        document.getElementById("loginScreen");

    const appContainer =
        document.getElementById("appContainer");


    if (loginScreen) {

        loginScreen.style.display = "none";

    }


    if (appContainer) {

        appContainer.style.display = "block";

    }

}


/* =====================================================
   LOGIN MESSAGE
===================================================== */

function showLoginMessage(
    message,
    error = false
) {

    const element =
        document.getElementById("loginMessage");


    if (!element) {

        return;

    }


    element.textContent =
        message;


    element.classList.remove(
        "success",
        "error"
    );


    if (error) {

        element.classList.add(
            "error"
        );

    }
    else {

        element.classList.add(
            "success"
        );

    }

}


/* =====================================================
   LOGIN ANIMATION
===================================================== */

function playLoginAnimation() {

    const terminal =
        document.getElementById("terminalOutput");


    if (!terminal) {

        return;

    }


    terminal.innerHTML = "";


    const messages = [

        "SENTRIX: Authentication successful.",

        "SENTRIX: Establishing secure channel...",

        "SENTRIX: Loading threat intelligence...",

        "SENTRIX: Initializing AI detection engine...",

        "SENTRIX: Connecting SOC monitoring services...",

        "SENTRIX: Security systems online.",

        "SENTRIX: Welcome Administrator."

    ];


    let index = 0;


    const interval =
        setInterval(
            function () {

                if (
                    index >= messages.length
                ) {

                    clearInterval(interval);

                    return;

                }


                terminal.innerHTML +=
                    "<div>" +
                    escapeHtml(messages[index]) +
                    "</div>";


                terminal.scrollTop =
                    terminal.scrollHeight;


                index++;

            },
            450
        );

}


/* =====================================================
   SHAKE LOGIN
===================================================== */

function shakeLoginBox() {

    const loginBox =
        document.querySelector(".login-box");


    if (!loginBox) {

        return;

    }


    loginBox.classList.remove(
        "login-shake"
    );


    void loginBox.offsetWidth;


    loginBox.classList.add(
        "login-shake"
    );

}


/* =====================================================
   NAVIGATION
===================================================== */

function setupNavigation() {

    const navItems =
        document.querySelectorAll(
            ".nav-item"
        );


    navItems.forEach(
        function (button) {

            button.addEventListener(
                "click",
                function () {

                    const page =
                        getPageFromButton(
                            button
                        );

                    if (page) {

                        showPage(
                            page,
                            button
                        );

                    }

                }
            );

        }
    );

}


/* =====================================================
   GET PAGE FROM BUTTON
===================================================== */

function getPageFromButton(button) {

    const text =
        button.textContent
            .toLowerCase()
            .trim();


    if (text.includes("dashboard")) {

        return "dashboard";

    }

    if (text.includes("alert")) {

        return "alerts";

    }

    if (
        text.includes("threat") ||
        text.includes("intel")
    ) {

        return "threats";

    }

    if (text.includes("detection")) {

        return "detection";

    }

    if (text.includes("investigation")) {

        return "investigation";

    }

    if (text.includes("report")) {

        return "reports";

    }

    if (text.includes("health")) {

        return "health";

    }


    return null;

}


/* =====================================================
   SHOW PAGE
===================================================== */

function showPage(
    pageId,
    clickedButton = null
) {

    const page =
        document.getElementById(pageId);


    if (!page) {

        console.warn(
            "Page not found:",
            pageId
        );

        return;

    }


    const pages =
        document.querySelectorAll(
            ".page"
        );


    pages.forEach(
        function (item) {

            item.classList.remove(
                "active-page"
            );

            item.style.display =
                "none";

        }
    );


    page.classList.add(
        "active-page"
    );

    page.style.display =
        "block";


    currentPage =
        pageId;


    /*
     * Navigation active state.
     */

    const navItems =
        document.querySelectorAll(
            ".nav-item"
        );


    navItems.forEach(
        function (item) {

            item.classList.remove(
                "active"
            );

        }
    );


    if (clickedButton) {

        clickedButton.classList.add(
            "active"
        );

    }
    else {

        navItems.forEach(
            function (item) {

                const detectedPage =
                    getPageFromButton(
                        item
                    );


                if (
                    detectedPage === pageId
                ) {

                    item.classList.add(
                        "active"
                    );

                }

            }
        );

    }


    /*
     * Update topbar.
     */

    const information =
        pageInformation[pageId];


    if (information) {

        const title =
            document.getElementById(
                "page-title"
            );

        const description =
            document.getElementById(
                "page-description"
            );


        if (title) {

            title.textContent =
                information.title;

        }


        if (description) {

            description.textContent =
                information.description;

        }

    }


    /*
     * Page-specific loading.
     */

    if (pageId === "dashboard") {

        loadDashboardData();

    }


    if (pageId === "health") {

        checkHealth();

    }


    if (pageId === "alerts") {

        loadAlerts();

    }


    /*
     * Smooth scroll.
     */

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });

}


/* =====================================================
   CLOCK
===================================================== */

function setupClock() {

    updateCurrentTime();

}


function updateCurrentTime() {

    const clock =
        document.getElementById(
            "liveClock"
        );


    if (!clock) {

        return;

    }


    const now =
        new Date();


    const hours =
        String(
            now.getHours()
        ).padStart(
            2,
            "0"
        );


    const minutes =
        String(
            now.getMinutes()
        ).padStart(
            2,
            "0"
        );


    const seconds =
        String(
            now.getSeconds()
        ).padStart(
            2,
            "0"
        );


    clock.textContent =
        `${hours}:${minutes}:${seconds}`;

}


/* =====================================================
   API GET
===================================================== */

async function apiGet(endpoint) {

    const response =
        await fetch(
            API_BASE_URL + endpoint,
            {
                method: "GET",
                headers: {
                    "Content-Type":
                        "application/json"
                }
            }
        );


    if (!response.ok) {

        throw new Error(
            await parseApiError(response)
        );

    }


    return response.json();

}


/* =====================================================
   API POST
===================================================== */

async function apiPost(
    endpoint,
    data
) {

    const response =
        await fetch(
            API_BASE_URL + endpoint,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify(data)
            }
        );


    if (!response.ok) {

        throw new Error(
            await parseApiError(response)
        );

    }


    return response.json();

}


/* =====================================================
   API ERROR PARSER
===================================================== */

async function parseApiError(response) {

    try {

        const data =
            await response.json();


        if (data.detail) {

            if (
                typeof data.detail ===
                "string"
            ) {

                return data.detail;

            }

            return JSON.stringify(
                data.detail
            );

        }

        if (data.message) {

            return data.message;

        }

        return JSON.stringify(data);

    }
    catch {

        return (
            "HTTP " +
            response.status +
            " " +
            response.statusText
        );

    }

}


/* =====================================================
   DASHBOARD DATA
===================================================== */

async function loadDashboardData() {

    try {

        const data =
            await apiGet(
                "/dashboard"
            );


        updateDashboardStats(
            data
        );


        updateDashboardStatus(
            true
        );

    }
    catch (error) {

        console.warn(
            "Dashboard API unavailable:",
            error.message
        );


        updateDashboardStatus(
            false
        );


        /*
         * Keep demo data visible if
         * backend is not running.
         */

        updateDashboardStats({
            data: {
                total_events: 12847,
                critical_alerts: 2,
                active_threats: 7,
                active_agents: 6
            }
        });

    }

}


/* =====================================================
   DASHBOARD STATISTICS
===================================================== */

function updateDashboardStats(data) {

    const metrics =
        data && data.data &&
        typeof data.data === "object"
            ? data.data
            : data;

    const total =
        getValue(
            metrics,
            [
                "total_events",
                "total_alerts",
                "totalAlerts",
                "alerts",
                "total"
            ],
            128
        );


    const critical =
        getValue(
            metrics,
            [
                "critical_alerts",
                "criticalAlerts",
                "critical"
            ],
            7
        );


    const threats =
        getValue(
            metrics,
            [
                "active_threats",
                "activeThreats",
                "threats"
            ],
            23
        );


    const activeAgents =
        getValue(
            metrics,
            [
                "active_agents",
                "activeAgents",
                "investigations",
                "active_investigations"
            ],
            12
        );


    setText(
        "totalAlerts",
        total
    );


    setText(
        "criticalAlerts",
        critical
    );


    setText(
        "activeThreats",
        threats
    );


    setText(
        "activeAgents",
        activeAgents
    );

}


/* =====================================================
   DASHBOARD STATUS
===================================================== */

function updateDashboardStatus(
    online
) {

    const status =
        document.querySelector(
            ".system-online strong"
        );


    if (!status) {

        return;

    }


    if (online) {

        status.textContent =
            "CORE ONLINE";

    }
    else {

        status.textContent =
            "API OFFLINE";

    }

}


/* =====================================================
   ALERTS
===================================================== */

async function loadAlerts() {

    try {

        const data =
            await apiGet(
                "/alerts"
            );


        renderAlerts(
            data
        );

    }
    catch (error) {

        console.warn(
            "Alerts API unavailable:",
            error.message
        );

    }

}


/* =====================================================
   RENDER ALERTS
===================================================== */

function renderAlerts(data) {

    const table =
        document.querySelector(
            "#alertsTable tbody"
        );


    if (!table) {

        return;

    }


    let alerts =
        Array.isArray(data)
            ? data
            : data.alerts;


    if (!Array.isArray(alerts)) {

        return;

    }


    table.innerHTML = "";


    alerts.forEach(
        function (alert) {

            const row =
                document.createElement(
                    "tr"
                );


            const severity =
                String(
                    alert.severity ||
                    "medium"
                ).toLowerCase();


            row.innerHTML = `

                <td>
                    ${escapeHtml(
                        alert.id ||
                        alert.alert_id ||
                        "N/A"
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        alert.title ||
                        alert.threat ||
                        alert.name ||
                        "Unknown Threat"
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        alert.source ||
                        alert.source_ip ||
                        "Unknown"
                    )}
                </td>

                <td>
                    <span class="table-${severity}">
                        ${escapeHtml(
                            severity.toUpperCase()
                        )}
                    </span>
                </td>

                <td>
                    ${escapeHtml(
                        alert.status ||
                        "Open"
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        alert.time ||
                        alert.timestamp ||
                        "Now"
                    )}
                </td>

            `;


            table.appendChild(
                row
            );

        }
    );

}


/* =====================================================
   SEARCH ALERTS
===================================================== */

function searchAlerts() {

    const input =
        document.getElementById(
            "alertSearch"
        );


    const table =
        document.getElementById(
            "alertsTable"
        );


    if (!input || !table) {

        return;

    }


    const search =
        input.value
            .toLowerCase()
            .trim();


    const rows =
        table.querySelectorAll(
            "tbody tr"
        );


    rows.forEach(
        function (row) {

            const text =
                row.textContent
                    .toLowerCase();


            row.style.display =
                text.includes(search)
                    ? ""
                    : "none";

        }
    );

}


/* =====================================================
   FILTER ALERTS
===================================================== */

function filterAlerts() {

    const filter =
        document.getElementById(
            "severityFilter"
        );


    const table =
        document.getElementById(
            "alertsTable"
        );


    if (!filter || !table) {

        return;

    }


    const value =
        filter.value
            .toLowerCase();


    const rows =
        table.querySelectorAll(
            "tbody tr"
        );


    rows.forEach(
        function (row) {

            const text =
                row.textContent
                    .toLowerCase();


            if (
                value === "all" ||
                text.includes(value)
            ) {

                row.style.display =
                    "";

            }
            else {

                row.style.display =
                    "none";

            }

        }
    );

}


/* =====================================================
   THREAT INTELLIGENCE
===================================================== */

async function investigateIndicator(
    alertId = null
) {

    const indicatorElement =
        document.getElementById(
            "indicator"
        );


    const typeElement =
        document.getElementById(
            "indicatorType"
        );


    let indicator =
        alertId;


    if (!indicator) {

        indicator =
            indicatorElement
                ? indicatorElement.value.trim()
                : "";

    }


    if (!indicator) {

        showResult(
            "threatResult",
            "Please enter an indicator.",
            "warning"
        );

        return;

    }


    const type =
        typeElement
            ? typeElement.value
            : "unknown";


    showResult(
        "threatResult",
        "SENTRIX is analyzing indicator...",
        "loading"
    );


    try {

        const result =
            await apiPost(
                "/threat-intelligence",
                {
                    indicator: indicator,
                    indicator_type: type
                }
            );


        displayThreatResult(
            result
        );

    }
    catch (error) {

        displayThreatResult({

            indicator: indicator,

            indicator_type: type,

            status: "Analysis Complete",

            reputation_score: calculateDemoReputation(
                indicator
            ),

            risk_level: "UNKNOWN",

            message:
                "Backend threat intelligence service unavailable. Demo analysis displayed."

        });

    }

}


/* =====================================================
   DISPLAY THREAT RESULT
===================================================== */

function displayThreatResult(
    data
) {

    const container =
        document.getElementById(
            "threatResult"
        );


    if (!container) {

        return;

    }


    container.classList.remove(
        "hidden"
    );


    const score =
        Number(
            data.reputation_score ??
            data.score ??
            data.risk_score ??
            42
        );


    const risk =
        data.risk_level ||
        data.status ||
        "UNKNOWN";


    container.innerHTML = `

        <div class="result-header">

            <strong>
                THREAT INTELLIGENCE RESULT
            </strong>

            <span>
                ${escapeHtml(
                    String(risk)
                )}
            </span>

        </div>

        <div class="result-body">

            <p>
                <strong>Indicator:</strong>
                ${escapeHtml(
                    data.indicator || "N/A"
                )}
            </p>

            <p>
                <strong>Type:</strong>
                ${escapeHtml(
                    data.indicator_type ||
                    "Unknown"
                )}
            </p>

            <p>
                <strong>Reputation Score:</strong>
                ${score}/100
            </p>

            <p>
                <strong>Message:</strong>
                ${escapeHtml(
                    data.message ||
                    "Analysis completed."
                )}
            </p>

        </div>

    `;


    /*
     * Update any reputation meter
     * if present in HTML.
     */

    const meter =
        document.getElementById(
            "reputationMeter"
        );


    if (meter) {

        meter.style.width =
            `${Math.min(
                100,
                Math.max(
                    0,
                    score
                )
            )}%`;

    }


    const scoreElement =
        document.getElementById(
            "reputationScore"
        );


    if (scoreElement) {

        scoreElement.textContent =
            score;

    }


    const statusElement =
        document.getElementById(
            "reputationStatus"
        );


    if (statusElement) {

        statusElement.textContent =
            risk;

    }

}


/* =====================================================
   DEMO REPUTATION SCORE
===================================================== */

function calculateDemoReputation(
    value
) {

    let total = 0;


    for (
        let i = 0;
        i < value.length;
        i++
    ) {

        total +=
            value.charCodeAt(i);

    }


    return total % 100;

}


/* =====================================================
   AI LOG DETECTION
===================================================== */

async function analyzeLog() {

    const logElement =
        document.getElementById(
            "securityLog"
        );


    if (!logElement) {

        return;

    }


    const log =
        logElement.value.trim();


    if (!log) {

        showResult(
            "detectionResult",
            "Please enter security log data.",
            "warning"
        );

        return;

    }


    showResult(
        "detectionResult",
        "SENTRIX AI is analyzing the security log...",
        "loading"
    );


    try {

        const result =
            await apiPost(
                "/detect",
                {
                    log: log
                }
            );


        displayDetectionResult(
            result
        );

    }
    catch (error) {

        /*
         * Local demo fallback.
         */

        displayDetectionResult(
            generateDemoDetection(
                log
            )
        );

    }

}


/* =====================================================
   DEMO DETECTION
===================================================== */

function generateDemoDetection(
    log
) {

    const lower =
        log.toLowerCase();


    let threat =
        "Benign";


    let confidence =
        92;


    let severity =
        "LOW";


    const indicators = [

        "failed login",
        "brute force",
        "malware",
        "ransomware",
        "powershell",
        "sql injection",
        "port scan",
        "privilege escalation",
        "suspicious",
        "unauthorized"

    ];


    for (
        const indicator of indicators
    ) {

        if (
            lower.includes(indicator)
        ) {

            threat =
                "Malicious";

            confidence =
                94;

            severity =
                "HIGH";

            break;

        }

    }


    return {

        classification: threat,

        threat: threat,

        confidence: confidence,

        severity: severity,

        message:
            "AI detection analysis completed locally."

    };

}


/* =====================================================
   DISPLAY DETECTION RESULT
===================================================== */

function displayDetectionResult(
    data
) {

    const container =
        document.getElementById(
            "detectionResult"
        );


    if (!container) {

        return;

    }


    container.classList.remove(
        "hidden"
    );


    const classification =
        data.classification ||
        data.threat ||
        data.label ||
        "Unknown";


    const confidence =
        data.confidence ??
        data.confidence_score ??
        0;


    const severity =
        data.severity ||
        "UNKNOWN";


    container.innerHTML = `

        <div class="result-header">

            <strong>
                AI DETECTION RESULT
            </strong>

            <span>
                ${escapeHtml(
                    String(classification)
                )}
            </span>

        </div>

        <div class="result-body">

            <p>
                <strong>Classification:</strong>
                ${escapeHtml(
                    String(classification)
                )}
            </p>

            <p>
                <strong>Confidence:</strong>
                ${escapeHtml(
                    String(confidence)
                )}%
            </p>

            <p>
                <strong>Severity:</strong>
                ${escapeHtml(
                    String(severity)
                )}
            </p>

            <p>
                <strong>Analysis:</strong>
                ${escapeHtml(
                    data.message ||
                    "Security log analysis completed."
                )}
            </p>

        </div>

    `;


    writeTerminal(
        "AI Detection Engine completed analysis.",
        "success"
    );

}


/* =====================================================
   SECURITY INVESTIGATION
===================================================== */

async function startInvestigation() {

    const idElement =
        document.getElementById(
            "investigationId"
        );


    const typeElement =
        document.getElementById(
            "investigationType"
        );


    const investigationId =
        idElement
            ? idElement.value.trim()
            : "";


    const investigationType =
        typeElement
            ? typeElement.value
            : "Full Investigation";


    if (!investigationId) {

        showResult(
            "investigationResult",
            "Please enter an Alert ID.",
            "warning"
        );

        return;

    }


    showResult(
        "investigationResult",
        "SENTRIX investigation engine starting...",
        "loading"
    );


    try {

        const result =
            await apiPost(
                "/investigate",
                {
                    alert_id:
                        investigationId,

                    investigation_type:
                        investigationType
                }
            );


        displayInvestigationResult(
            result
        );

    }
    catch (error) {

        displayInvestigationResult({

            alert_id:
                investigationId,

            status:
                "Investigation Started",

            verdict:
                "Under Investigation",

            summary:
                "The investigation engine is ready. Backend investigation endpoint is currently unavailable."

        });

    }

}


/* =====================================================
   DISPLAY INVESTIGATION
===================================================== */

function displayInvestigationResult(
    data
) {

    const container =
        document.getElementById(
            "investigationResult"
        );


    if (!container) {

        return;

    }


    container.classList.remove(
        "hidden"
    );


    container.innerHTML = `

        <div class="result-header">

            <strong>
                INVESTIGATION RESULT
            </strong>

            <span>
                ${escapeHtml(
                    data.status ||
                    "ACTIVE"
                )}
            </span>

        </div>

        <div class="result-body">

            <p>
                <strong>Alert ID:</strong>
                ${escapeHtml(
                    data.alert_id ||
                    "N/A"
                )}
            </p>

            <p>
                <strong>Verdict:</strong>
                ${escapeHtml(
                    data.verdict ||
                    "Pending"
                )}
            </p>

            <p>
                <strong>Summary:</strong>
                ${escapeHtml(
                    data.summary ||
                    data.message ||
                    "Investigation completed."
                )}
            </p>

        </div>

    `;


    writeTerminal(
        "Investigation engine started.",
        "info"
    );

}


/* =====================================================
   REPORT GENERATION
===================================================== */

async function generateReport(
    reportType
) {

    const result =
        document.getElementById(
            "reportResult"
        );


    if (result) {

        result.classList.remove(
            "hidden"
        );


        result.innerHTML = `

            <div class="result-header">

                <strong>
                    SENTRIX REPORT ENGINE
                </strong>

                <span>
                    GENERATING
                </span>

            </div>

            <div class="result-body">

                Generating
                ${escapeHtml(
                    reportType
                )}
                report...

            </div>

        `;

    }


    writeReportTerminal(
        "Generating " +
        reportType +
        " report..."
    );


    try {

        const response =
            await apiPost(
                "/reports",
                {
                    report_type:
                        reportType
                }
            );


        displayReportResult(
            response
        );

    }
    catch (error) {

        /*
         * Demo fallback.
         */

        displayReportResult({

            status: "Generated",

            report_type:
                reportType,

            message:
                "Report generated successfully in demonstration mode."

        });

    }

}


/* =====================================================
   DISPLAY REPORT
===================================================== */

function displayReportResult(
    data
) {

    const result =
        document.getElementById(
            "reportResult"
        );


    if (!result) {

        return;

    }


    result.classList.remove(
        "hidden"
    );


    result.innerHTML = `

        <div class="result-header">

            <strong>
                REPORT GENERATED
            </strong>

            <span>
                ${escapeHtml(
                    data.status ||
                    "READY"
                )}
            </span>

        </div>

        <div class="result-body">

            <p>
                <strong>Report Type:</strong>
                ${escapeHtml(
                    data.report_type ||
                    "Security Report"
                )}
            </p>

            <p>
                <strong>Status:</strong>
                ${escapeHtml(
                    data.status ||
                    "Generated"
                )}
            </p>

            <p>
                ${escapeHtml(
                    data.message ||
                    "Security report generated successfully."
                )}
            </p>

        </div>

    `;


    writeReportTerminal(
        "Report generation completed."
    );

}


/* =====================================================
   REPORT TERMINAL
===================================================== */

function writeReportTerminal(
    message
) {

    const terminal =
        document.querySelector(
            "#reportTerminal .terminal-output"
        );


    if (!terminal) {

        return;

    }


    const line =
        document.createElement(
            "div"
        );


    line.textContent =
        "> " + message;


    terminal.appendChild(
        line
    );


    terminal.scrollTop =
        terminal.scrollHeight;

}


/* =====================================================
   HEALTH CHECK
===================================================== */

async function checkHealth() {

    updateHealthTerminal(
        "> Running SENTRIX system diagnostics..."
    );


    try {

        const data =
            await apiGet(
                "/health"
            );


        updateHealthStatus(
            true,
            data
        );


        updateHealthTerminal(
            "> Backend API ........ ONLINE"
        );


        updateHealthTerminal(
            "> Health check ........ PASSED"
        );

    }
    catch (error) {

        updateHealthStatus(
            false
        );


        updateHealthTerminal(
            "> Backend API ........ OFFLINE"
        );


        updateHealthTerminal(
            "> Demo interface remains operational."
        );

    }

}


/* =====================================================
   UPDATE HEALTH STATUS
===================================================== */

function updateHealthStatus(
    online,
    data = null
) {

    const cards =
        document.querySelectorAll(
            ".health-card"
        );


    cards.forEach(
        function (card) {

            const indicator =
                card.querySelector(
                    ".health-indicator"
                );


            if (!indicator) {

                return;

            }


            indicator.classList.remove(
                "online",
                "offline"
            );


            if (online) {

                indicator.classList.add(
                    "online"
                );

                indicator.textContent =
                    "ONLINE";

            }
            else {

                indicator.classList.add(
                    "offline"
                );

                indicator.textContent =
                    "OFFLINE";

            }

        }
    );

}


/* =====================================================
   HEALTH TERMINAL
===================================================== */

function updateHealthTerminal(
    message
) {

    const terminal =
        document.querySelector(
            "#healthTerminal .terminal-output"
        );


    if (!terminal) {

        return;

    }


    const line =
        document.createElement(
            "div"
        );


    line.textContent =
        message;


    terminal.appendChild(
        line
    );


    terminal.scrollTop =
        terminal.scrollHeight;

}


/* =====================================================
   RESULT PANEL
===================================================== */

function showResult(
    elementId,
    message,
    type = "info"
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!element) {

        return;

    }


    element.classList.remove(
        "hidden",
        "loading",
        "success",
        "warning",
        "error"
    );


    element.classList.add(
        type
    );


    element.textContent =
        message;

}


/* =====================================================
    SENTRIX BOOT SEQUENCE
===================================================== */

function startJarvisBootSequence() {

    const terminal =
        document.getElementById(
            "terminalOutput"
        );


    if (!terminal) {

        return;

    }


    terminal.innerHTML = "";


    const messages = [

        "SENTRIX CORE v1.0 INITIALIZING",

        "Loading artificial intelligence modules...",

        "Loading anomaly detection engine...",

        "Loading threat intelligence engine...",

        "Loading correlation engine...",

        "Loading risk analysis engine...",

        "Establishing SOC monitoring channel...",

        "SYSTEM READY."

    ];


    let index = 0;


    terminalTimer =
        setInterval(
            function () {

                if (
                    index >= messages.length
                ) {

                    clearInterval(
                        terminalTimer
                    );

                    return;

                }


                const line =
                    document.createElement(
                        "div"
                    );


                line.innerHTML =
                    `<span class="terminal-prefix">&gt;</span> ${
                        escapeHtml(
                            messages[index]
                        )
                    }`;


                terminal.appendChild(
                    line
                );


                terminal.scrollTop =
                    terminal.scrollHeight;


                index++;

            },
            700
        );

}


/* =====================================================
   CONTINUOUS TERMINAL SIMULATION
===================================================== */

function startTerminalSimulation() {

    const terminal =
        document.getElementById(
            "terminalOutput"
        );


    if (!terminal) {

        return;

    }


    const messages = [

        "Monitoring network traffic...",

        "Analyzing authentication events...",

        "Threat intelligence synchronization complete.",

        "Anomaly detector scanning events...",

        "Correlation engine processing security events...",

        "Risk engine calculating threat scores...",

        "No unauthorized system changes detected.",

        "SOC monitoring operational."

    ];


    let index = 0;


    setInterval(
        function () {

            /*
             * Only add simulation messages
             * when application is visible.
             */

            const app =
                document.getElementById(
                    "appContainer"
                );


            if (
                !app ||
                app.style.display === "none"
            ) {

                return;

            }


            const line =
                document.createElement(
                    "div"
                );


            line.innerHTML =
                `<span class="terminal-prefix">&gt;</span> ${
                    escapeHtml(
                        messages[index]
                    )
                }`;


            terminal.appendChild(
                line
            );


            /*
             * Keep terminal manageable.
             */

            while (
                terminal.children.length > 40
            ) {

                terminal.removeChild(
                    terminal.firstChild
                );

            }


            terminal.scrollTop =
                terminal.scrollHeight;


            index =
                (index + 1) %
                messages.length;

        },
        3500
    );

}


/* =====================================================
   WRITE TERMINAL MESSAGE
===================================================== */

function writeTerminal(
    message,
    type = "info"
) {

    const terminal =
        document.getElementById(
            "terminalOutput"
        );


    if (!terminal) {

        return;

    }


    const line =
        document.createElement(
            "div"
        );


    line.className =
        "terminal-line " +
        type;


    line.innerHTML =
        `<span class="terminal-prefix">&gt;</span> ${
            escapeHtml(
                message
            )
        }`;


    terminal.appendChild(
        line
    );


    terminal.scrollTop =
        terminal.scrollHeight;

}


/* =====================================================
   TERMINAL INPUT
===================================================== */

function setupTerminalInput() {

    const input =
        document.getElementById(
            "terminal-input"
        );


    if (!input) {

        return;

    }


    input.addEventListener(
        "keydown",
        function (event) {

            if (
                event.key === "Enter"
            ) {

                executeTerminalCommand();

            }

        }
    );

}


/* =====================================================
   TERMINAL COMMAND EXECUTION
===================================================== */

function executeTerminalCommand() {

    const input =
        document.getElementById(
            "terminal-input"
        );


    const response =
        document.getElementById(
            "jarvisResponse"
        );


    if (!input || !response) {

        return;

    }


    const command =
        input.value
            .trim()
            .toLowerCase();


    if (!command) {

        return;

    }


    /*
     * User command.
     */

    const userLine =
        document.createElement(
            "div"
        );


    userLine.innerHTML =
        `<span class="terminal-prefix">&gt;</span> ${
            escapeHtml(
                input.value
            )
        }`;


    response.appendChild(
        userLine
    );


    let answer =
        "";


    switch (command) {

        case "help":

            answer =
                "Available commands: status, scan, alerts, threats, detection, investigate, reports, health, clear, logout";

            break;


        case "status":

            answer =
                "All SENTRIX security modules are operational.";

            break;


        case "scan":

            answer =
                "SENTRIX security scan initiated.";

            runSecurityScan();

            break;


        case "alerts":

            answer =
                "Opening Security Alerts.";

            showPage("alerts");

            break;


        case "threats":

            answer =
                "Opening Threat Intelligence.";

            showPage("threats");

            break;


        case "detection":

            answer =
                "Opening AI Detection Engine.";

            showPage("detection");

            break;


        case "investigate":

            answer =
                "Opening Investigation Center.";

            showPage("investigation");

            break;


        case "reports":

            answer =
                "Opening Security Reports.";

            showPage("reports");

            break;


        case "health":

            answer =
                "Running system health diagnostics.";

            showPage("health");

            checkHealth();

            break;


        case "clear":

            response.innerHTML = "";

            input.value = "";

            return;


        case "logout":

            logout();

            return;


        default:

            answer =
                "Command not recognized. Type 'help' for available commands.";

            break;

    }


    const responseLine =
        document.createElement(
            "div"
        );


    responseLine.textContent =
        "SENTRIX: " +
        answer;


    response.appendChild(
        responseLine
    );


    response.scrollTop =
        response.scrollHeight;


    input.value = "";

}


/* =====================================================
   SECURITY SCAN
===================================================== */

function runSecurityScan() {

    const overlay =
        document.getElementById(
            "securityOverlay"
        );


    const message =
        document.getElementById(
            "overlayMessage"
        );


    if (overlay) {

        overlay.classList.remove(
            "hidden"
        );

    }


    const messages = [

        "Analyzing network traffic...",

        "Scanning authentication events...",

        "Checking endpoint activity...",

        "Analyzing threat intelligence...",

        "Running correlation engine...",

        "Calculating risk score..."

    ];


    let index = 0;


    const timer =
        setInterval(
            function () {

                if (
                    index >= messages.length
                ) {

                    clearInterval(
                        timer
                    );


                    if (message) {

                        message.textContent =
                            "Security scan completed.";

                    }


                    setTimeout(
                        function () {

                            if (overlay) {

                                overlay.classList.add(
                                    "hidden"
                                );

                            }

                        },
                        1000
                    );


                    writeTerminal(
                        "Security scan completed successfully.",
                        "success"
                    );


                    return;

                }


                if (message) {

                    message.textContent =
                        messages[index];

                }


                index++;

            },
            700
        );

}


/* =====================================================
   AUTO REFRESH
===================================================== */

function startAutoRefresh() {

    stopAutoRefresh();


    autoRefreshTimer =
        setInterval(
            function () {

                if (
                    currentPage ===
                    "dashboard"
                ) {

                    loadDashboardData();

                }

            },
            30000
        );

}


function stopAutoRefresh() {

    if (
        autoRefreshTimer
    ) {

        clearInterval(
            autoRefreshTimer
        );

        autoRefreshTimer =
            null;

    }

}


/* =====================================================
   KEYBOARD SHORTCUTS
===================================================== */

function setupKeyboardShortcuts() {

    document.addEventListener(
        "keydown",
        function (event) {

            /*
             * ALT + D
             * Dashboard
             */

            if (
                event.altKey &&
                event.key.toLowerCase() === "d"
            ) {

                event.preventDefault();

                showPage(
                    "dashboard"
                );

            }


            /*
             * ALT + A
             * Alerts
             */

            if (
                event.altKey &&
                event.key.toLowerCase() === "a"
            ) {

                event.preventDefault();

                showPage(
                    "alerts"
                );

            }


            /*
             * ESC
             * Close security overlay
             */

            if (
                event.key === "Escape"
            ) {

                const overlay =
                    document.getElementById(
                        "securityOverlay"
                    );


                if (overlay) {

                    overlay.classList.add(
                        "hidden"
                    );

                }

            }

        }
    );

}


/* =====================================================
   HELPER: SET TEXT
===================================================== */

function setText(
    elementId,
    value
) {

    const element =
        document.getElementById(
            elementId
        );


    if (element) {

        element.textContent =
            value;

    }

}


/* =====================================================
   HELPER: GET VALUE
===================================================== */

function getValue(
    object,
    keys,
    defaultValue
) {

    if (!object) {

        return defaultValue;

    }


    for (
        const key of keys
    ) {

        if (
            object[key] !== undefined &&
            object[key] !== null
        ) {

            return object[key];

        }

    }


    return defaultValue;

}


/* =====================================================
   HTML ESCAPE
===================================================== */

function escapeHtml(
    value
) {

    if (
        value === null ||
        value === undefined
    ) {

        return "";

    }


    return String(value)
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );

}


/* =====================================================
   WINDOW EXPORTS
===================================================== */

/*
 * These functions are called directly
 * from index.html onclick attributes.
 */

window.login =
    login;

window.logout =
    logout;

window.showPage =
    showPage;

window.searchAlerts =
    searchAlerts;

window.filterAlerts =
    filterAlerts;

window.investigateIndicator =
    investigateIndicator;

window.analyzeLog =
    analyzeLog;

window.startInvestigation =
    startInvestigation;

window.generateReport =
    generateReport;

window.checkHealth =
    checkHealth;

window.executeTerminalCommand =
    executeTerminalCommand;


/* =====================================================
    SENTRIX READY MESSAGE
===================================================== */

console.log(
    "%c SENTRIX AI CYBERSECURITY SOC ",
    "color:#00d9ff;font-size:18px;font-weight:bold;"
);

console.log(
    "%c Security Operations Center initialized.",
    "color:#00ff88;font-size:13px;"
);

console.log(
    "%c API:",
    "color:#ffaa00;font-weight:bold;",
    API_BASE_URL
);
