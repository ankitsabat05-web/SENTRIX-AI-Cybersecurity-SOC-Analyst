"""
=========================================================
AI CYBERSECURITY SOC ANALYST
Machine Learning Prediction Module
=========================================================

File:
    backend/ml/predict.py

Purpose:
    Analyze security logs and predict whether they
    contain suspicious or malicious activity.

This module currently uses a lightweight rule-based
prediction engine. It can later be replaced with a
trained Machine Learning model.
=========================================================
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import joblib
import pandas as pd


MODEL_PATH = Path(__file__).resolve().parent / "security_model.joblib"


# =========================================================
# THREAT PATTERNS
# =========================================================

THREAT_PATTERNS = {

    "brute_force": [
        "failed login",
        "failed password",
        "authentication failure",
        "invalid password",
        "login failed",
        "too many login attempts",
        "multiple failed",
        "account locked",
    ],

    "port_scan": [
        "port scan",
        "port scanning",
        "nmap",
        "multiple ports",
        "syn scan",
        "scan detected",
    ],

    "malware": [
        "malware",
        "trojan",
        "ransomware",
        "virus",
        "worm",
        "malicious file",
        "suspicious executable",
    ],

    "sql_injection": [
        "union select",
        "' or '1'='1",
        "' or 1=1",
        "sql injection",
        "drop table",
        "information_schema",
    ],

    "xss": [
        "<script>",
        "javascript:",
        "onerror=",
        "onload=",
        "cross site scripting",
        "xss attack",
    ],

    "command_injection": [
        "command injection",
        "; whoami",
        "; ls",
        "; cat /etc/passwd",
        "| whoami",
        "cmd.exe",
        "powershell",
    ],

    "privilege_escalation": [
        "privilege escalation",
        "root access",
        "administrator privileges",
        "elevated privileges",
        "unauthorized admin",
    ],

    "data_exfiltration": [
        "data exfiltration",
        "large outbound",
        "unusual outbound",
        "sensitive data transfer",
        "database dump",
    ],
}


# =========================================================
# EXTRACT IP ADDRESSES
# =========================================================

def extract_ip_addresses(log: str) -> List[str]:
    """
    Extract IPv4 addresses from the security log.
    """

    if not log:
        return []

    pattern = (
        r"\b"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|"
        r"[1-9]?\d)"
        r"(?:\."
        r"(?:25[0-5]|2[0-4]\d|1\d\d|"
        r"[1-9]?\d)"
        r"){3}"
        r"\b"
    )

    matches = re.findall(pattern, log)

    return list(dict.fromkeys(matches))


# =========================================================
# EXTRACT PORT NUMBERS
# =========================================================

def extract_ports(log: str) -> List[int]:
    """
    Extract port numbers from the log.
    """

    if not log:
        return []

    matches = re.findall(
        r"\b(?:port|dst_port|src_port)"
        r"[\s:=]+(\d{1,5})\b",
        log,
        flags=re.IGNORECASE,
    )

    ports = []

    for value in matches:

        try:

            port = int(value)

            if 0 <= port <= 65535:
                ports.append(port)

        except ValueError:

            continue

    return list(dict.fromkeys(ports))


# =========================================================
# DETECT THREAT PATTERNS
# =========================================================

def detect_threat_patterns(
    log: str,
) -> Dict[str, List[str]]:
    """
    Detect known threat patterns inside a security log.
    """

    normalized_log = log.lower()

    detected = {}

    for threat_type, patterns in THREAT_PATTERNS.items():

        matches = []

        for pattern in patterns:

            if pattern.lower() in normalized_log:

                matches.append(pattern)

        if matches:

            detected[threat_type] = matches

    return detected


# =========================================================
# CALCULATE THREAT SCORE
# =========================================================

def calculate_threat_score(
    log: str,
    detected_patterns: Dict[str, List[str]],
) -> int:
    """
    Calculate a threat score between 0 and 100.
    """

    score = 0

    # -----------------------------------------------------
    # Score based on detected threats
    # -----------------------------------------------------

    for threat_type, matches in detected_patterns.items():

        if threat_type in {
            "malware",
            "command_injection",
            "data_exfiltration",
        }:

            score += 30

        elif threat_type in {
            "sql_injection",
            "privilege_escalation",
        }:

            score += 25

        elif threat_type in {
            "brute_force",
            "port_scan",
            "xss",
        }:

            score += 20

        score += min(
            len(matches) * 5,
            15,
        )

    # -----------------------------------------------------
    # Multiple IP addresses
    # -----------------------------------------------------

    ip_addresses = extract_ip_addresses(log)

    if len(ip_addresses) >= 5:

        score += 15

    elif len(ip_addresses) >= 2:

        score += 5

    # -----------------------------------------------------
    # Multiple ports
    # -----------------------------------------------------

    ports = extract_ports(log)

    if len(ports) >= 10:

        score += 20

    elif len(ports) >= 5:

        score += 10

    # -----------------------------------------------------
    # Suspicious keywords
    # -----------------------------------------------------

    suspicious_keywords = [
        "attack",
        "exploit",
        "unauthorized",
        "suspicious",
        "malicious",
        "intrusion",
        "breach",
        "compromised",
    ]

    keyword_count = sum(
        1
        for keyword in suspicious_keywords
        if keyword in log.lower()
    )

    score += min(
        keyword_count * 5,
        20,
    )

    return min(score, 100)


# =========================================================
# DETERMINE SEVERITY
# =========================================================

def determine_severity(score: int) -> str:
    """
    Convert threat score into severity.
    """

    if score >= 90:

        return "critical"

    elif score >= 70:

        return "high"

    elif score >= 40:

        return "medium"

    return "low"


# =========================================================
# DETERMINE PRIMARY THREAT
# =========================================================

def determine_threat_type(
    detected_patterns: Dict[str, List[str]],
) -> str:
    """
    Determine the primary threat category.
    """

    if not detected_patterns:

        return "benign"

    priority = [
        "malware",
        "command_injection",
        "sql_injection",
        "data_exfiltration",
        "privilege_escalation",
        "brute_force",
        "port_scan",
        "xss",
    ]

    for threat_type in priority:

        if threat_type in detected_patterns:

            return threat_type

    return next(
        iter(detected_patterns)
    )


# =========================================================
# GENERATE SOC RECOMMENDATION
# =========================================================

def generate_recommendation(
    threat_type: str,
    severity: str,
) -> str:
    """
    Generate a recommended SOC response.
    """

    recommendations = {

        "brute_force":
            "Investigate repeated authentication failures and review the source IP.",

        "port_scan":
            "Investigate the source IP and review firewall and network logs.",

        "malware":
            "Isolate the affected endpoint and perform malware analysis.",

        "sql_injection":
            "Review application logs and inspect database requests for malicious input.",

        "xss":
            "Review application input handling and apply proper validation and output encoding.",

        "command_injection":
            "Investigate the affected host and review executed commands and processes.",

        "privilege_escalation":
            "Review privileged account activity and unauthorized privilege changes.",

        "data_exfiltration":
            "Investigate outbound traffic and identify the destination and transferred data.",

        "benign":
            "No strong malicious indicators were detected. Continue monitoring.",

    }

    recommendation = recommendations.get(
        threat_type,
        "Continue monitoring the event and investigate related security activity.",
    )

    if severity == "critical":

        recommendation += (
            " Immediate SOC investigation and containment should be considered."
        )

    elif severity == "high":

        recommendation += (
            " Prioritize this event for analyst review."
        )

    return recommendation


# =========================================================
# MAIN PREDICTION FUNCTION
# =========================================================

def predict_threat(
    log: str,
) -> Dict[str, Any]:
    """
    Analyze a security log and return the prediction.

    Parameters
    ----------
    log : str
        Raw security log.

    Returns
    -------
    Dict[str, Any]
        Prediction result.
    """

    if not isinstance(log, str):

        raise TypeError(
            "Security log must be a string."
        )

    log = log.strip()

    if not log:

        raise ValueError(
            "Security log cannot be empty."
        )

    # -----------------------------------------------------
    # Detect patterns
    # -----------------------------------------------------

    detected_patterns = detect_threat_patterns(log)

    # -----------------------------------------------------
    # Calculate score
    # -----------------------------------------------------

    score = calculate_threat_score(
        log,
        detected_patterns,
    )

    # -----------------------------------------------------
    # Determine severity
    # -----------------------------------------------------

    severity = determine_severity(score)

    # -----------------------------------------------------
    # Determine threat type
    # -----------------------------------------------------

    threat_type = determine_threat_type(
        detected_patterns,
    )

    # -----------------------------------------------------
    # Extract indicators
    # -----------------------------------------------------

    ip_addresses = extract_ip_addresses(log)

    ports = extract_ports(log)

    # -----------------------------------------------------
    # Generate recommendation
    # -----------------------------------------------------

    recommendation = generate_recommendation(
        threat_type,
        severity,
    )

    # -----------------------------------------------------
    # Determine prediction
    # -----------------------------------------------------

    prediction = (
        "malicious"
        if threat_type != "benign"
        else "benign"
    )

    # -----------------------------------------------------
    # Confidence
    # -----------------------------------------------------

    confidence = round(
        min(
            0.99,
            0.50 + (score / 200),
        ),
        2,
    )

    # -----------------------------------------------------
    # Final result
    # -----------------------------------------------------

    result = {

        "prediction": prediction,

        "threat_type": threat_type,

        "threat_score": score,

        "severity": severity,

        "confidence": confidence,

        "detected_patterns": detected_patterns,

        "ip_addresses": ip_addresses,

        "ports": ports,

        "recommendation": recommendation,

        "timestamp": (
            datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        ),
    }

    return result


# =========================================================
# SIMPLE PREDICT WRAPPER
# =========================================================

def _build_model_features(log: str) -> Dict[str, float]:
    """Extract numeric feature values from a raw log string for the trained model."""
    text = (log or "").lower()
    sanitized_text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ", text)

    failed_login_keywords = [
        "failed login",
        "login failed",
        "authentication failure",
        "invalid password",
        "multiple failed",
        "too many login attempts",
        "repeated failed login",
    ]

    suspicious_login = any(keyword in text for keyword in failed_login_keywords)
    brute_force = any(keyword in text for keyword in ["failed login", "login failed", "multiple failed", "invalid password"])

    def count_keyword_hits(pattern: str) -> int:
        return len(re.findall(re.escape(pattern), sanitized_text))

    explicit_failed_logins = 0
    explicit_match = re.search(r"(?:failed|invalid)\s+(?:login|password)[^\n\r]*?(\d+)", sanitized_text)
    if explicit_match:
        try:
            explicit_failed_logins = int(explicit_match.group(1))
        except ValueError:
            explicit_failed_logins = 0

    failed_logins = explicit_failed_logins or (7 if suspicious_login else 0)
    if not explicit_failed_logins and suspicious_login:
        failed_logins += count_keyword_hits("failed login") * 2 + count_keyword_hits("multiple failed") * 3

    def find_first_int(pattern: str) -> int:
        match = re.search(pattern, sanitized_text, flags=re.IGNORECASE)
        if not match:
            return 0
        try:
            return int(match.group(1))
        except (TypeError, ValueError):
            return 0

    bytes_value = find_first_int(r"(\d+)\s*bytes")
    request_count = find_first_int(r"(\d+)\s*requests?")
    packet_count = find_first_int(r"(\d+)\s*packets?")
    session_duration = find_first_int(r"(\d+)\s*seconds?")
    payload_size = find_first_int(r"(\d+)\s*payload\s*size")
    unique_ports = len(re.findall(r"port\s+(\d{1,5})", sanitized_text, flags=re.IGNORECASE))
    connection_rate = 0.0

    rate_match = re.search(r"connection\s*rate\s*[:=]\s*(\d+(?:\.\d+)?)", sanitized_text, flags=re.IGNORECASE)
    if rate_match:
        connection_rate = float(rate_match.group(1))

    port_match = re.search(r"port\s+(\d{1,5})", sanitized_text, flags=re.IGNORECASE)
    port = int(port_match.group(1)) if port_match else 80

    login_success = 1 if "successful login" in text or "login succeeded" in text else 0
    if suspicious_login:
        login_success = 0

    if suspicious_login:
        request_count = max(request_count, 180)
        packet_count = max(packet_count, 350)
        connection_rate = max(connection_rate, 6.0)
        payload_size = max(payload_size, 1200)
        if not bytes_value:
            bytes_value = 8000

    if brute_force and port in {22, 23, 3389}:
        failed_logins = max(failed_logins, 8)
        request_count = max(request_count, 220)
        packet_count = max(packet_count, 420)
        connection_rate = max(connection_rate, 8.0)

    return {
        "port": port,
        "failed_logins": failed_logins,
        "bytes": bytes_value,
        "request_count": request_count,
        "login_success": login_success,
        "packet_count": packet_count,
        "session_duration": session_duration,
        "unique_ports": unique_ports,
        "connection_rate": connection_rate,
        "payload_size": payload_size,
    }


def load_model():
    """Load the trained ML model if present."""
    if not MODEL_PATH.exists():
        return None

    try:
        return joblib.load(MODEL_PATH)
    except Exception:
        return None


def predict(log: str) -> Dict[str, Any]:
    """Predict malicious activity using the trained model when available."""
    model = load_model()
    if model is not None:
        features = pd.DataFrame([_build_model_features(log)])
        prediction = int(model.predict(features)[0])
        probabilities = model.predict_proba(features)[0]
        class_probabilities = dict(zip(model.classes_, probabilities))
        predicted_probability = float(class_probabilities[prediction])
        malicious_probability = float(class_probabilities.get(1, 0.0))
        label = "malicious" if prediction == 1 else "benign"

        score = int(round(malicious_probability * 100))
        return {
            "prediction": label,
            "threat_type": label,
            "threat_score": score,
            "severity": "critical" if prediction == 1 and score >= 80 else "high" if prediction == 1 else "low",
            "confidence": round(predicted_probability, 2),
            "detected_patterns": [],
            "ip_addresses": [],
            "ports": [],
            "recommendation": (
                "Isolate the affected system and investigate the source of the suspicious activity."
                if prediction == 1
                else "No suspicious activity detected by the trained model."
            ),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    return predict_threat(log)


# =========================================================
# TEST
# =========================================================

if __name__ == "__main__":

    import json

    sample_log = (
        "2026-09-27 22:15:43 "
        "Failed login from 192.168.1.105 "
        "multiple failed password attempts "
        "port 22"
    )

    result = predict_threat(
        sample_log
    )

    print(
        json.dumps(
            result,
            indent=4,
        )
    )

