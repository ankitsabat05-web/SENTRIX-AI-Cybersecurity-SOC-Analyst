"""
Detection Agent
---------------

Responsible for detecting potentially suspicious activity from
processed security logs.

Detection sources:
- Event type
- Severity
- IOC presence
- Threat intelligence
- MITRE ATT&CK mapping
- Suspicious keywords

This module is intentionally separated from the API routes so
that the detection engine can later be replaced or enhanced
with ML/LLM-based detection.
"""

from typing import Any, Dict, List


class DetectionAgent:
    """
    Security detection engine for the SOC Analyst.

    The agent combines multiple security signals and produces
    a structured detection result.
    """

    # ---------------------------------------------------------
    # SUSPICIOUS EVENTS
    # ---------------------------------------------------------

    HIGH_RISK_EVENTS = {
        "ransomware",
        "malware",
        "brute_force",
        "sql_injection",
        "xss",
        "dos_attack",
        "malicious_download"
    }

    MEDIUM_RISK_EVENTS = {
        "network_scanning",
        "powershell_activity",
        "authentication_failure"
    }

    # ---------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # ---------------------------------------------------------

    SUSPICIOUS_KEYWORDS = [
        "malware",
        "ransomware",
        "trojan",
        "backdoor",
        "brute force",
        "failed login",
        "port scan",
        "network scan",
        "powershell",
        "sql injection",
        "xss",
        "exploit",
        "payload",
        "malicious",
        "unauthorized",
        "credential theft",
        "data exfiltration"
    ]

    # ---------------------------------------------------------
    # EVENT DETECTION
    # ---------------------------------------------------------

    @classmethod
    def detect_event(
        cls,
        event_type: str
    ) -> Dict[str, Any]:
        """
        Detect risk based on the event type.
        """

        event_type = event_type.lower().strip()

        if event_type in cls.HIGH_RISK_EVENTS:
            return {
                "detected": True,
                "confidence": 0.90,
                "reason": (
                    f"Event type '{event_type}' is associated "
                    "with potentially malicious activity."
                )
            }

        if event_type in cls.MEDIUM_RISK_EVENTS:
            return {
                "detected": True,
                "confidence": 0.70,
                "reason": (
                    f"Event type '{event_type}' requires "
                    "further investigation."
                )
            }

        return {
            "detected": False,
            "confidence": 0.20,
            "reason": "No high-confidence malicious event type detected."
        }

    # ---------------------------------------------------------
    # KEYWORD DETECTION
    # ---------------------------------------------------------

    @classmethod
    def detect_keywords(
        cls,
        log_text: str
    ) -> Dict[str, Any]:
        """
        Search the log for suspicious security-related keywords.
        """

        if not log_text:
            return {
                "detected": False,
                "keywords": [],
                "count": 0
            }

        text = log_text.lower()

        detected_keywords = [
            keyword
            for keyword in cls.SUSPICIOUS_KEYWORDS
            if keyword in text
        ]

        return {
            "detected": len(detected_keywords) > 0,
            "keywords": detected_keywords,
            "count": len(detected_keywords)
        }

    # ---------------------------------------------------------
    # IOC DETECTION
    # ---------------------------------------------------------

    @staticmethod
    def detect_iocs(
        iocs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Determine whether the processed log contains IOCs.
        """

        if not iocs:
            return {
                "detected": False,
                "ioc_count": 0
            }

        ip_addresses = iocs.get(
            "ip_addresses",
            []
        )

        domains = iocs.get(
            "domains",
            []
        )

        urls = iocs.get(
            "urls",
            []
        )

        hashes = iocs.get(
            "hashes",
            {}
        )

        hash_count = (
            len(hashes.get("md5", []))
            + len(hashes.get("sha1", []))
            + len(hashes.get("sha256", []))
        )

        total_iocs = (
            len(ip_addresses)
            + len(domains)
            + len(urls)
            + hash_count
        )

        return {
            "detected": total_iocs > 0,
            "ioc_count": total_iocs,
            "ip_count": len(ip_addresses),
            "domain_count": len(domains),
            "url_count": len(urls),
            "hash_count": hash_count
        }

    # ---------------------------------------------------------
    # THREAT INTELLIGENCE ANALYSIS
    # ---------------------------------------------------------

    @staticmethod
    def analyze_threat_intelligence(
        threat_intelligence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze the result generated by ThreatIntelService.
        """

        if not threat_intelligence:
            return {
                "detected": False,
                "threat_score": 0,
                "threat_level": "unknown"
            }

        threat_score = threat_intelligence.get(
            "highest_threat_score",
            0
        )

        threat_level = threat_intelligence.get(
            "overall_threat_level",
            "unknown"
        )

        return {
            "detected": threat_score > 0,
            "threat_score": threat_score,
            "threat_level": threat_level
        }

    # ---------------------------------------------------------
    # MITRE ATT&CK ANALYSIS
    # ---------------------------------------------------------

    @staticmethod
    def analyze_mitre(
        mitre_data: Any
    ) -> Dict[str, Any]:
        """
        Analyze MITRE ATT&CK mappings associated with the event.
        """

        if not mitre_data:
            return {
                "detected": False,
                "technique_count": 0,
                "techniques": []
            }

        if isinstance(mitre_data, list):
            techniques = mitre_data
        else:
            techniques = []

        technique_ids = []

        for technique in techniques:
            if isinstance(technique, dict):
                technique_id = technique.get(
                    "technique_id"
                )

                if technique_id:
                    technique_ids.append(
                        technique_id
                    )

        return {
            "detected": len(technique_ids) > 0,
            "technique_count": len(technique_ids),
            "techniques": technique_ids
        }

    # ---------------------------------------------------------
    # RISK SCORE
    # ---------------------------------------------------------

    @staticmethod
    def calculate_risk_score(
        event_detection: Dict[str, Any],
        keyword_detection: Dict[str, Any],
        ioc_detection: Dict[str, Any],
        threat_intelligence: Dict[str, Any],
        mitre_detection: Dict[str, Any]
    ) -> int:
        """
        Calculate an overall detection risk score.

        Score range:
            0 - 100
        """

        score = 0

        # Event detection
        if event_detection.get("detected"):
            confidence = event_detection.get(
                "confidence",
                0
            )

            score += int(confidence * 40)

        # Suspicious keywords
        keyword_count = keyword_detection.get(
            "count",
            0
        )

        score += min(
            keyword_count * 5,
            20
        )

        # IOC presence
        if ioc_detection.get("detected"):
            score += min(
                ioc_detection.get("ioc_count", 0) * 5,
                15
            )

        # Threat intelligence
        ti_score = threat_intelligence.get(
            "threat_score",
            0
        )

        score += min(
            ti_score,
            20
        )

        # MITRE mapping
        if mitre_detection.get("detected"):
            score += min(
                mitre_detection.get(
                    "technique_count",
                    0
                ) * 5,
                10
            )

        return min(score, 100)

    # ---------------------------------------------------------
    # RISK CLASSIFICATION
    # ---------------------------------------------------------

    @staticmethod
    def classify_risk(
        score: int
    ) -> str:
        """
        Convert risk score to severity.
        """

        if score >= 80:
            return "critical"

        if score >= 60:
            return "high"

        if score >= 30:
            return "medium"

        if score > 0:
            return "low"

        return "informational"

    # ---------------------------------------------------------
    # MAIN DETECTION FUNCTION
    # ---------------------------------------------------------

    @classmethod
    def detect(
        cls,
        processed_log: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform complete security detection.

        Expected input:

        {
            "event_type": "...",
            "cleaned_log": "...",
            "iocs": {...},
            "mitre_attack": [...],
            "threat_intelligence": {...}
        }
        """

        event_type = processed_log.get(
            "event_type",
            "unknown"
        )

        log_text = processed_log.get(
            "cleaned_log",
            processed_log.get(
                "raw_log",
                ""
            )
        )

        # -----------------------------------------------------
        # Individual detection layers
        # -----------------------------------------------------

        event_detection = cls.detect_event(
            event_type
        )

        keyword_detection = cls.detect_keywords(
            log_text
        )

        ioc_detection = cls.detect_iocs(
            processed_log.get(
                "iocs",
                {}
            )
        )

        threat_intelligence = (
            cls.analyze_threat_intelligence(
                processed_log.get(
                    "threat_intelligence",
                    {}
                )
            )
        )

        mitre_detection = cls.analyze_mitre(
            processed_log.get(
                "mitre_attack",
                []
            )
        )

        # -----------------------------------------------------
        # Calculate risk
        # -----------------------------------------------------

        risk_score = cls.calculate_risk_score(
            event_detection,
            keyword_detection,
            ioc_detection,
            threat_intelligence,
            mitre_detection
        )

        risk_level = cls.classify_risk(
            risk_score
        )

        # -----------------------------------------------------
        # Final detection decision
        # -----------------------------------------------------

        detected = (
            event_detection["detected"]
            or keyword_detection["detected"]
            or threat_intelligence["detected"]
        )

        # -----------------------------------------------------
        # Generate explanation
        # -----------------------------------------------------

        reasons: List[str] = []

        if event_detection["detected"]:
            reasons.append(
                event_detection["reason"]
            )

        if keyword_detection["detected"]:
            reasons.append(
                "Suspicious keywords detected: "
                + ", ".join(
                    keyword_detection["keywords"]
                )
            )

        if ioc_detection["detected"]:
            reasons.append(
                f"{ioc_detection['ioc_count']} IOC(s) "
                "were extracted from the log."
            )

        if threat_intelligence["detected"]:
            reasons.append(
                "Threat intelligence produced a "
                f"{threat_intelligence['threat_level']} "
                "threat level."
            )

        if mitre_detection["detected"]:
            reasons.append(
                "The event maps to MITRE ATT&CK technique(s): "
                + ", ".join(
                    mitre_detection["techniques"]
                )
            )

        if not reasons:
            reasons.append(
                "No significant suspicious indicators were detected."
            )

        # -----------------------------------------------------
        # Return detection result
        # -----------------------------------------------------

        return {
            "detected": detected,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "event_type": event_type,

            "event_detection": event_detection,

            "keyword_detection": keyword_detection,

            "ioc_detection": ioc_detection,

            "threat_intelligence": threat_intelligence,

            "mitre_detection": mitre_detection,

            "reasons": reasons
        }


# -------------------------------------------------------------
# HELPER FUNCTION
# -------------------------------------------------------------

def detect_threat(
    processed_log: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Convenience function for threat detection.
    """

    return DetectionAgent.detect(
        processed_log
    )