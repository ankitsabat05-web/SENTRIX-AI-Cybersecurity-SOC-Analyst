"""
Threat Intelligence Agent
-------------------------

Responsible for analyzing Indicators of Compromise (IOCs)
and converting threat-intelligence results into structured
security findings.

The agent works with:

- IP addresses
- Domains
- URLs
- MD5 hashes
- SHA1 hashes
- SHA256 hashes
- Threat intelligence scores
- Threat intelligence reputation
- Security logs

This agent does not automatically block or modify any IOC.
It only produces intelligence and recommendations.
"""

from typing import Any, Dict, List

from app.services.threat_intel import ThreatIntelService


class ThreatIntelAgent:
    """
    Threat Intelligence analysis agent.
    """

    # ---------------------------------------------------------
    # IOC RISK THRESHOLDS
    # ---------------------------------------------------------

    CRITICAL_SCORE = 80
    HIGH_SCORE = 60
    MEDIUM_SCORE = 30

    # ---------------------------------------------------------
    # INITIALIZATION
    # ---------------------------------------------------------

    def __init__(self) -> None:
        self.threat_intel_service = ThreatIntelService

    # ---------------------------------------------------------
    # ANALYZE SINGLE IOC
    # ---------------------------------------------------------

    def analyze_ioc(
        self,
        ioc: str
    ) -> Dict[str, Any]:
        """
        Analyze a single IOC using ThreatIntelService.
        """

        if not ioc or not ioc.strip():
            return {
                "ioc": ioc,
                "status": "invalid",
                "error": "IOC cannot be empty"
            }

        result = self.threat_intel_service.analyze_ioc(
            ioc
        )

        return self._enrich_result(
            result
        )

    # ---------------------------------------------------------
    # ENRICH IOC RESULT
    # ---------------------------------------------------------

    @classmethod
    def _enrich_result(
        cls,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Add intelligence interpretation to an IOC result.
        """

        score = result.get(
            "threat_score",
            0
        )

        reputation = result.get(
            "reputation",
            "unknown"
        )

        threat_level = cls.classify_score(
            score
        )

        return {
            **result,

            "threat_level": threat_level,

            "is_suspicious": (
                score >= cls.MEDIUM_SCORE
            ),

            "requires_investigation": (
                score >= cls.MEDIUM_SCORE
            ),

            "confidence": cls.calculate_confidence(
                result
            )
        }

    # ---------------------------------------------------------
    # SCORE CLASSIFICATION
    # ---------------------------------------------------------

    @classmethod
    def classify_score(
        cls,
        score: int
    ) -> str:
        """
        Convert a threat score into a threat level.
        """

        if score >= cls.CRITICAL_SCORE:
            return "critical"

        if score >= cls.HIGH_SCORE:
            return "high"

        if score >= cls.MEDIUM_SCORE:
            return "medium"

        if score > 0:
            return "low"

        return "unknown"

    # ---------------------------------------------------------
    # CONFIDENCE
    # ---------------------------------------------------------

    @staticmethod
    def calculate_confidence(
        result: Dict[str, Any]
    ) -> float:
        """
        Calculate a basic confidence value.

        This represents confidence in the local analysis,
        not confirmation that an IOC is malicious.
        """

        if not result.get(
            "valid",
            False
        ):
            return 0.0

        ioc_type = result.get(
            "ioc_type",
            "unknown"
        )

        # Exact cryptographic hash format gives
        # high confidence in IOC classification.
        if ioc_type in {
            "md5",
            "sha1",
            "sha256"
        }:
            return 0.95

        if ioc_type == "ip":
            return 0.90

        if ioc_type == "domain":
            return 0.90

        if ioc_type == "url":
            return 0.85

        return 0.50

    # ---------------------------------------------------------
    # ANALYZE MULTIPLE IOCs
    # ---------------------------------------------------------

    def analyze_iocs(
        self,
        iocs: List[str]
    ) -> Dict[str, Any]:
        """
        Analyze multiple IOCs.
        """

        if not iocs:
            return {
                "total": 0,
                "analyzed": 0,
                "suspicious": 0,
                "findings": []
            }

        findings = []

        for ioc in iocs:

            result = self.analyze_ioc(
                ioc
            )

            findings.append(
                result
            )

        suspicious = [
            finding
            for finding in findings
            if finding.get(
                "is_suspicious",
                False
            )
        ]

        return {
            "total": len(iocs),
            "analyzed": len(findings),
            "suspicious": len(suspicious),
            "findings": findings
        }

    # ---------------------------------------------------------
    # EXTRACT IOCs FROM PROCESSED LOG
    # ---------------------------------------------------------

    @staticmethod
    def extract_iocs_from_log(
        processed_log: Dict[str, Any]
    ) -> List[str]:
        """
        Extract all IOCs from LogProcessor output.
        """

        iocs_data = processed_log.get(
            "iocs",
            {}
        )

        iocs: List[str] = []

        # IP addresses
        iocs.extend(
            iocs_data.get(
                "ip_addresses",
                []
            )
        )

        # Domains
        iocs.extend(
            iocs_data.get(
                "domains",
                []
            )
        )

        # URLs
        iocs.extend(
            iocs_data.get(
                "urls",
                []
            )
        )

        # Hashes
        hashes = iocs_data.get(
            "hashes",
            {}
        )

        iocs.extend(
            hashes.get(
                "md5",
                []
            )
        )

        iocs.extend(
            hashes.get(
                "sha1",
                []
            )
        )

        iocs.extend(
            hashes.get(
                "sha256",
                []
            )
        )

        return list(
            dict.fromkeys(iocs)
        )

    # ---------------------------------------------------------
    # ANALYZE PROCESSED LOG
    # ---------------------------------------------------------

    def analyze_log(
        self,
        processed_log: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze all IOCs extracted from a processed log.
        """

        if not processed_log:
            return {
                "status": "no_data",
                "threat_intelligence": {}
            }

        iocs = self.extract_iocs_from_log(
            processed_log
        )

        intelligence = self.analyze_iocs(
            iocs
        )

        return {
            "status": "analyzed",

            "event_type": processed_log.get(
                "event_type",
                "unknown"
            ),

            "ioc_count": len(iocs),

            "threat_intelligence": intelligence
        }

    # ---------------------------------------------------------
    # GENERATE THREAT FINDINGS
    # ---------------------------------------------------------

    @staticmethod
    def generate_findings(
        intelligence: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Convert intelligence results into SOC findings.
        """

        findings = []

        for result in intelligence.get(
            "findings",
            []
        ):

            if not result.get(
                "is_suspicious",
                False
            ):
                continue

            findings.append({
                "ioc": result.get(
                    "ioc"
                ),

                "ioc_type": result.get(
                    "ioc_type"
                ),

                "threat_level": result.get(
                    "threat_level",
                    "unknown"
                ),

                "threat_score": result.get(
                    "threat_score",
                    0
                ),

                "confidence": result.get(
                    "confidence",
                    0
                ),

                "description": (
                    f"IOC {result.get('ioc')} "
                    f"was classified as "
                    f"{result.get('threat_level', 'unknown')} "
                    "risk by the available intelligence analysis."
                )
            })

        return findings

    # ---------------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------------

    @staticmethod
    def generate_recommendations(
        findings: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Generate defensive recommendations from
        threat-intelligence findings.
        """

        recommendations: List[str] = []

        if not findings:
            return [
                "No high-confidence malicious IOC was identified by the current local analysis.",
                "Continue monitoring and correlate future security events."
            ]

        threat_levels = {
            finding.get(
                "threat_level",
                "unknown"
            )
            for finding in findings
        }

        if "critical" in threat_levels:

            recommendations.extend([
                "Escalate the affected IOC for immediate SOC investigation.",
                "Review systems and accounts associated with the IOC.",
                "Preserve relevant logs and forensic evidence."
            ])

        elif "high" in threat_levels:

            recommendations.extend([
                "Investigate systems communicating with the identified IOC.",
                "Correlate the IOC with endpoint, firewall and authentication logs."
            ])

        else:

            recommendations.extend([
                "Investigate the identified IOC in the context of related security events.",
                "Continue monitoring for additional activity associated with the IOC."
            ])

        recommendations.append(
            "Validate IOC reputation using approved external threat-intelligence sources before taking blocking or containment actions."
        )

        return list(
            dict.fromkeys(
                recommendations
            )
        )

    # ---------------------------------------------------------
    # COMPLETE THREAT INTELLIGENCE REPORT
    # ---------------------------------------------------------

    def generate_report(
        self,
        processed_log: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate a complete threat-intelligence report
        for a processed security log.
        """

        analysis = self.analyze_log(
            processed_log
        )

        intelligence = analysis.get(
            "threat_intelligence",
            {}
        )

        findings = self.generate_findings(
            intelligence
        )

        recommendations = self.generate_recommendations(
            findings
        )

        threat_levels = [
            finding.get(
                "threat_level",
                "unknown"
            )
            for finding in findings
        ]

        if "critical" in threat_levels:
            overall_level = "critical"

        elif "high" in threat_levels:
            overall_level = "high"

        elif "medium" in threat_levels:
            overall_level = "medium"

        elif "low" in threat_levels:
            overall_level = "low"

        else:
            overall_level = "unknown"

        return {
            "status": "completed",

            "overall_threat_level": (
                overall_level
            ),

            "ioc_count": analysis.get(
                "ioc_count",
                0
            ),

            "suspicious_ioc_count": len(
                findings
            ),

            "findings": findings,

            "recommendations": recommendations
        }


# -------------------------------------------------------------
# GLOBAL AGENT INSTANCE
# -------------------------------------------------------------

threat_intel_agent = ThreatIntelAgent()


# -------------------------------------------------------------
# HELPER FUNCTION
# -------------------------------------------------------------

def analyze_threat_intelligence(
    processed_log: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Convenience function for threat-intelligence analysis.
    """

    return threat_intel_agent.generate_report(
        processed_log
    )