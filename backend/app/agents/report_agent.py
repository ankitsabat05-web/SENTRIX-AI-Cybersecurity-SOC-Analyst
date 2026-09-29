"""
SOC Report Agent
----------------

Generates structured cybersecurity investigation reports
from the outputs of:

- Detection Agent
- Threat Hunter Agent
- Investigator Agent
- Threat Intelligence
- MITRE ATT&CK

The Report Agent does not execute remediation actions.
It summarizes evidence and produces an analyst-friendly report.
"""

from datetime import datetime
from typing import Any, Dict, List


class ReportAgent:
    """
    Generates SOC incident reports.
    """

    # ---------------------------------------------------------
    # SEVERITY ORDER
    # ---------------------------------------------------------

    SEVERITY_PRIORITY = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0,
        "unknown": 0
    }

    # ---------------------------------------------------------
    # DETERMINE SEVERITY
    # ---------------------------------------------------------

    @classmethod
    def determine_severity(
        cls,
        investigation: Dict[str, Any],
        detection: Dict[str, Any],
        hunting: Dict[str, Any]
    ) -> str:
        """
        Determine the highest severity observed across
        detection, hunting and investigation results.
        """

        candidates: List[str] = []

        # Detection severity
        detection_level = detection.get(
            "risk_level"
        )

        if detection_level:
            candidates.append(
                detection_level
            )

        # Investigation severity
        investigation_level = investigation.get(
            "investigation_level"
        )

        if investigation_level:
            candidates.append(
                investigation_level
            )

        # Hunting severity
        hunting_status = hunting.get(
            "overall_status"
        )

        if hunting_status == "suspicious":
            candidates.append("medium")

        elif hunting_status in {
            "high",
            "critical"
        }:
            candidates.append(
                hunting_status
            )

        if not candidates:
            return "informational"

        return max(
            candidates,
            key=lambda severity: cls.SEVERITY_PRIORITY.get(
                severity,
                0
            )
        )

    # ---------------------------------------------------------
    # EXTRACT IOC SUMMARY
    # ---------------------------------------------------------

    @staticmethod
    def summarize_iocs(
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a concise IOC summary.
        """

        ip_addresses = evidence.get(
            "ip_addresses",
            []
        )

        domains = evidence.get(
            "domains",
            []
        )

        urls = evidence.get(
            "urls",
            []
        )

        hashes = evidence.get(
            "hashes",
            {}
        )

        md5 = hashes.get(
            "md5",
            []
        )

        sha1 = hashes.get(
            "sha1",
            []
        )

        sha256 = hashes.get(
            "sha256",
            []
        )

        total = (
            len(ip_addresses)
            + len(domains)
            + len(urls)
            + len(md5)
            + len(sha1)
            + len(sha256)
        )

        return {
            "total": total,
            "ip_addresses": ip_addresses,
            "domains": domains,
            "urls": urls,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256
        }

    # ---------------------------------------------------------
    # MITRE SUMMARY
    # ---------------------------------------------------------

    @staticmethod
    def summarize_mitre(
        techniques: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Return a clean MITRE ATT&CK technique summary.
        """

        result = []

        for technique in techniques:

            if not isinstance(
                technique,
                dict
            ):
                continue

            result.append({
                "technique_id": technique.get(
                    "technique_id",
                    "unknown"
                ),
                "name": technique.get(
                    "name",
                    "Unknown"
                ),
                "tactic": technique.get(
                    "tactic",
                    "Unknown"
                )
            })

        return result

    # ---------------------------------------------------------
    # FINDINGS SUMMARY
    # ---------------------------------------------------------

    @staticmethod
    def summarize_findings(
        hunting: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Extract important threat-hunting findings.
        """

        findings = hunting.get(
            "findings",
            []
        )

        summary = []

        for finding in findings:

            if not isinstance(
                finding,
                dict
            ):
                continue

            summary.append({
                "hunt_type": finding.get(
                    "hunt_type",
                    "unknown"
                ),
                "severity": finding.get(
                    "severity",
                    "unknown"
                ),
                "confidence": finding.get(
                    "confidence",
                    0
                ),
                "description": finding.get(
                    "description",
                    ""
                )
            })

        return summary

    # ---------------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------------

    @staticmethod
    def generate_recommendations(
        severity: str,
        investigation: Dict[str, Any],
        detection: Dict[str, Any]
    ) -> List[str]:
        """
        Generate defensive recommendations based on
        investigation findings.

        These are recommendations only and are not executed
        automatically.
        """

        recommendations = []

        event_types = (
            investigation
            .get("evidence", {})
            .get("event_types", [])
        )

        if severity == "critical":

            recommendations.extend([
                "Escalate the incident to the appropriate SOC analyst.",
                "Preserve relevant logs and forensic evidence.",
                "Review affected systems and accounts for additional indicators.",
                "Consider containment of affected assets according to incident-response procedures."
            ])

        elif severity == "high":

            recommendations.extend([
                "Investigate the affected accounts and systems.",
                "Review authentication and endpoint telemetry.",
                "Preserve relevant security logs.",
                "Escalate if additional malicious indicators are confirmed."
            ])

        elif severity == "medium":

            recommendations.extend([
                "Continue monitoring the affected systems.",
                "Review related events and network activity.",
                "Validate the identified indicators using approved threat-intelligence sources."
            ])

        else:

            recommendations.extend([
                "Continue monitoring the activity.",
                "Review related events if additional suspicious indicators appear."
            ])

        if "brute_force" in event_types:
            recommendations.append(
                "Review repeated authentication failures and consider additional authentication controls."
            )

        if "powershell_activity" in event_types:
            recommendations.append(
                "Review PowerShell execution logs and command-line telemetry."
            )

        if "network_scanning" in event_types:
            recommendations.append(
                "Investigate the source of network scanning activity and review exposed services."
            )

        if "malicious_download" in event_types:
            recommendations.append(
                "Inspect downloaded files and review endpoint activity associated with the download."
            )

        if "ransomware" in event_types:
            recommendations.append(
                "Follow the organization's ransomware incident-response procedure and preserve forensic evidence."
            )

        return list(
            dict.fromkeys(recommendations)
        )

    # ---------------------------------------------------------
    # ANALYST SUMMARY
    # ---------------------------------------------------------

    @staticmethod
    def generate_analyst_summary(
        severity: str,
        investigation: Dict[str, Any],
        detection: Dict[str, Any],
        hunting: Dict[str, Any]
    ) -> str:
        """
        Generate a concise analyst-readable summary.
        """

        summary = investigation.get(
            "summary",
            ""
        )

        risk_score = detection.get(
            "risk_score",
            0
        )

        findings_count = hunting.get(
            "findings_count",
            0
        )

        parts = []

        if summary:
            parts.append(summary)

        parts.append(
            f"Final report severity: {severity}."
        )

        parts.append(
            f"Detection risk score: {risk_score}/100."
        )

        parts.append(
            f"Threat-hunting findings: {findings_count}."
        )

        return " ".join(parts)

    # ---------------------------------------------------------
    # GENERATE REPORT
    # ---------------------------------------------------------

    @classmethod
    def generate_report(
        cls,
        investigation: Dict[str, Any],
        detection: Dict[str, Any] | None = None,
        hunting: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """
        Generate the complete SOC incident report.
        """

        detection = detection or {}
        hunting = hunting or {}

        evidence = investigation.get(
            "evidence",
            {}
        )

        severity = cls.determine_severity(
            investigation,
            detection,
            hunting
        )

        ioc_summary = cls.summarize_iocs(
            evidence
        )

        mitre_summary = cls.summarize_mitre(
            investigation.get(
                "mitre_techniques",
                []
            )
        )

        findings_summary = cls.summarize_findings(
            hunting
        )

        recommendations = cls.generate_recommendations(
            severity,
            investigation,
            detection
        )

        analyst_summary = cls.generate_analyst_summary(
            severity,
            investigation,
            detection,
            hunting
        )

        # -----------------------------------------------------
        # REPORT
        # -----------------------------------------------------

        return {
            "report_id": cls.generate_report_id(),

            "generated_at": datetime.utcnow().isoformat(),

            "report_type": "SOC Incident Investigation Report",

            "severity": severity,

            "status": (
                "requires_investigation"
                if severity in {
                    "critical",
                    "high",
                    "medium"
                }
                else "monitoring"
            ),

            "analyst_summary": analyst_summary,

            "risk": {
                "risk_score": detection.get(
                    "risk_score",
                    0
                ),
                "risk_level": detection.get(
                    "risk_level",
                    "unknown"
                )
            },

            "investigation": {
                "events_investigated": investigation.get(
                    "events_investigated",
                    0
                ),
                "investigation_level": investigation.get(
                    "investigation_level",
                    "unknown"
                ),
                "summary": investigation.get(
                    "summary",
                    ""
                )
            },

            "indicators_of_compromise": ioc_summary,

            "attack_stages": investigation.get(
                "attack_stages",
                []
            ),

            "mitre_attack": mitre_summary,

            "correlations": investigation.get(
                "correlations",
                []
            ),

            "affected_assets": investigation.get(
                "affected_assets",
                {}
            ),

            "threat_hunting": {
                "overall_status": hunting.get(
                    "overall_status",
                    "unknown"
                ),
                "findings_count": hunting.get(
                    "findings_count",
                    0
                ),
                "findings": findings_summary
            },

            "timeline": investigation.get(
                "timeline",
                []
            ),

            "detection_reasons": detection.get(
                "reasons",
                []
            ),

            "recommendations": recommendations
        }

    # ---------------------------------------------------------
    # REPORT ID
    # ---------------------------------------------------------

    @staticmethod
    def generate_report_id() -> str:
        """
        Generate a unique report identifier.
        """

        timestamp = datetime.utcnow().strftime(
            "%Y%m%d%H%M%S%f"
        )

        return f"SOC-{timestamp}"


# -------------------------------------------------------------
# HELPER FUNCTION
# -------------------------------------------------------------

def create_soc_report(
    investigation: Dict[str, Any],
    detection: Dict[str, Any] | None = None,
    hunting: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    """
    Convenience function for generating a SOC report.
    """

    return ReportAgent.generate_report(
        investigation,
        detection,
        hunting
    )