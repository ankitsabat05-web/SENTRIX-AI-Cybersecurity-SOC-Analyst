"""
Risk Engine
-----------

Combines multiple security signals into a normalized risk score.

Inputs:

- Detection Agent
- Threat Intelligence Agent
- Anomaly Detector
- Correlation Engine
- MITRE ATT&CK information
- Investigation findings

Output:

- Risk score: 0-100
- Risk level
- Contributing factors
- Recommended priority

This is a rule-based risk engine. The score represents the
configured risk model and should not be treated as a definitive
measure of compromise.
"""

from typing import Any, Dict, List


class RiskEngine:
    """
    Calculates and explains cybersecurity risk scores.
    """

    # ---------------------------------------------------------
    # RISK WEIGHTS
    # ---------------------------------------------------------

    WEIGHTS = {
        "detection": 0.30,
        "threat_intelligence": 0.20,
        "anomaly": 0.20,
        "correlation": 0.20,
        "investigation": 0.10
    }

    # ---------------------------------------------------------
    # RISK LEVEL THRESHOLDS
    # ---------------------------------------------------------

    CRITICAL_THRESHOLD = 80
    HIGH_THRESHOLD = 60
    MEDIUM_THRESHOLD = 30

    # ---------------------------------------------------------
    # NORMALIZE SCORE
    # ---------------------------------------------------------

    @staticmethod
    def normalize_score(
        score: Any
    ) -> float:
        """
        Normalize a score to the range 0-100.
        """

        try:
            numeric_score = float(
                score
            )
        except (
            TypeError,
            ValueError
        ):
            return 0.0

        return round(
            max(
                0.0,
                min(
                    numeric_score,
                    100.0
                )
            ),
            2
        )

    # ---------------------------------------------------------
    # DETECTION SCORE
    # ---------------------------------------------------------

    def calculate_detection_score(
        self,
        detection: Dict[str, Any]
    ) -> float:
        """
        Extract the detection risk score.
        """

        return self.normalize_score(
            detection.get(
                "risk_score",
                0
            )
        )

    # ---------------------------------------------------------
    # THREAT INTELLIGENCE SCORE
    # ---------------------------------------------------------

    def calculate_threat_intel_score(
        self,
        threat_intelligence: Dict[str, Any]
    ) -> float:
        """
        Calculate risk from threat-intelligence findings.

        The highest IOC score is used because one highly
        suspicious IOC can be significant.
        """

        findings = threat_intelligence.get(
            "findings",
            []
        )

        scores: List[float] = []

        for finding in findings:

            score = finding.get(
                "threat_score",
                0
            )

            scores.append(
                self.normalize_score(
                    score
                )
            )

        if not scores:
            return 0.0

        return max(
            scores
        )

    # ---------------------------------------------------------
    # ANOMALY SCORE
    # ---------------------------------------------------------

    def calculate_anomaly_score(
        self,
        anomaly_result: Dict[str, Any]
    ) -> float:
        """
        Extract anomaly score.
        """

        return self.normalize_score(
            anomaly_result.get(
                "anomaly_score",
                0
            )
        )

    # ---------------------------------------------------------
    # CORRELATION SCORE
    # ---------------------------------------------------------

    def calculate_correlation_score(
        self,
        correlation_result: Dict[str, Any]
    ) -> float:
        """
        Calculate risk from event correlation.

        The strongest event relationship is used.
        """

        correlations = correlation_result.get(
            "correlations",
            []
        )

        scores = []

        for correlation in correlations:

            score = correlation.get(
                "correlation_score",
                0
            )

            scores.append(
                self.normalize_score(
                    score
                )
            )

        # Attack chains increase the correlation signal.
        attack_chains = correlation_result.get(
            "attack_chains",
            []
        )

        if attack_chains:

            for chain in attack_chains:

                confidence = chain.get(
                    "confidence",
                    "medium"
                )

                if confidence == "high":
                    scores.append(90)

                elif confidence == "medium":
                    scores.append(60)

                else:
                    scores.append(30)

        if not scores:
            return 0.0

        return max(
            scores
        )

    # ---------------------------------------------------------
    # INVESTIGATION SCORE
    # ---------------------------------------------------------

    def calculate_investigation_score(
        self,
        investigation: Dict[str, Any]
    ) -> float:
        """
        Convert investigation findings into a risk signal.
        """

        score = 0.0

        investigation_level = str(
            investigation.get(
                "investigation_level",
                ""
            )
        ).lower()

        level_scores = {
            "critical": 100,
            "high": 80,
            "medium": 50,
            "low": 25
        }

        score = level_scores.get(
            investigation_level,
            0
        )

        # Additional evidence increases the signal.
        evidence = investigation.get(
            "evidence",
            {}
        )

        if evidence.get(
            "ip_addresses"
        ):
            score += 5

        if evidence.get(
            "domains"
        ):
            score += 5

        if evidence.get(
            "urls"
        ):
            score += 5

        if evidence.get(
            "hashes"
        ):
            score += 10

        return self.normalize_score(
            score
        )

    # ---------------------------------------------------------
    # COMBINED RISK SCORE
    # ---------------------------------------------------------

    def calculate_risk_score(
        self,
        detection: Dict[str, Any] | None = None,
        threat_intelligence: Dict[str, Any] | None = None,
        anomaly_result: Dict[str, Any] | None = None,
        correlation_result: Dict[str, Any] | None = None,
        investigation: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """
        Calculate the weighted overall risk score.
        """

        detection = detection or {}
        threat_intelligence = (
            threat_intelligence or {}
        )
        anomaly_result = (
            anomaly_result or {}
        )
        correlation_result = (
            correlation_result or {}
        )
        investigation = (
            investigation or {}
        )

        detection_score = (
            self.calculate_detection_score(
                detection
            )
        )

        threat_intel_score = (
            self.calculate_threat_intel_score(
                threat_intelligence
            )
        )

        anomaly_score = (
            self.calculate_anomaly_score(
                anomaly_result
            )
        )

        correlation_score = (
            self.calculate_correlation_score(
                correlation_result
            )
        )

        investigation_score = (
            self.calculate_investigation_score(
                investigation
            )
        )

        weighted_score = (
            detection_score
            * self.WEIGHTS["detection"]
        )

        weighted_score += (
            threat_intel_score
            * self.WEIGHTS[
                "threat_intelligence"
            ]
        )

        weighted_score += (
            anomaly_score
            * self.WEIGHTS["anomaly"]
        )

        weighted_score += (
            correlation_score
            * self.WEIGHTS["correlation"]
        )

        weighted_score += (
            investigation_score
            * self.WEIGHTS["investigation"]
        )

        final_score = self.normalize_score(
            weighted_score
        )

        risk_level = self.classify_risk(
            final_score
        )

        factors = self.generate_risk_factors(
            detection_score,
            threat_intel_score,
            anomaly_score,
            correlation_score,
            investigation_score
        )

        return {
            "risk_score": final_score,

            "risk_level": risk_level,

            "priority": self.determine_priority(
                risk_level
            ),

            "component_scores": {
                "detection": detection_score,
                "threat_intelligence": (
                    threat_intel_score
                ),
                "anomaly": anomaly_score,
                "correlation": correlation_score,
                "investigation": investigation_score
            },

            "weights": self.WEIGHTS,

            "risk_factors": factors
        }

    # ---------------------------------------------------------
    # RISK CLASSIFICATION
    # ---------------------------------------------------------

    @classmethod
    def classify_risk(
        cls,
        score: float
    ) -> str:
        """
        Convert numerical risk score into a risk level.
        """

        if score >= cls.CRITICAL_THRESHOLD:
            return "critical"

        if score >= cls.HIGH_THRESHOLD:
            return "high"

        if score >= cls.MEDIUM_THRESHOLD:
            return "medium"

        if score > 0:
            return "low"

        return "informational"

    # ---------------------------------------------------------
    # PRIORITY
    # ---------------------------------------------------------

    @staticmethod
    def determine_priority(
        risk_level: str
    ) -> str:
        """
        Determine SOC investigation priority.
        """

        priorities = {
            "critical": "P1",
            "high": "P2",
            "medium": "P3",
            "low": "P4",
            "informational": "P5"
        }

        return priorities.get(
            risk_level,
            "P5"
        )

    # ---------------------------------------------------------
    # RISK FACTORS
    # ---------------------------------------------------------

    @staticmethod
    def generate_risk_factors(
        detection_score: float,
        threat_intel_score: float,
        anomaly_score: float,
        correlation_score: float,
        investigation_score: float
    ) -> List[Dict[str, Any]]:
        """
        Explain which security signals contributed to risk.
        """

        factors = []

        components = [
            (
                "detection",
                detection_score
            ),
            (
                "threat_intelligence",
                threat_intel_score
            ),
            (
                "anomaly",
                anomaly_score
            ),
            (
                "correlation",
                correlation_score
            ),
            (
                "investigation",
                investigation_score
            )
        ]

        for name, score in components:

            if score >= 80:
                severity = "critical"

            elif score >= 60:
                severity = "high"

            elif score >= 30:
                severity = "medium"

            elif score > 0:
                severity = "low"

            else:
                continue

            factors.append({
                "component": name,
                "score": score,
                "severity": severity
            })

        factors.sort(
            key=lambda item: item["score"],
            reverse=True
        )

        return factors

    # ---------------------------------------------------------
    # RISK EXPLANATION
    # ---------------------------------------------------------

    @staticmethod
    def generate_explanation(
        risk_result: Dict[str, Any]
    ) -> str:
        """
        Generate a concise explanation of the final risk score.
        """

        score = risk_result.get(
            "risk_score",
            0
        )

        level = risk_result.get(
            "risk_level",
            "informational"
        )

        factors = risk_result.get(
            "risk_factors",
            []
        )

        if not factors:

            return (
                f"The calculated risk score is {score}/100 "
                "with no significant contributing security signals."
            )

        top_factors = factors[:3]

        factor_names = [
            factor["component"]
            for factor in top_factors
        ]

        return (
            f"The calculated risk score is {score}/100 "
            f"({level}). The strongest contributing signals "
            f"were: {', '.join(factor_names)}."
        )

    # ---------------------------------------------------------
    # COMPLETE ANALYSIS
    # ---------------------------------------------------------

    def analyze(
        self,
        detection: Dict[str, Any] | None = None,
        threat_intelligence: Dict[str, Any] | None = None,
        anomaly_result: Dict[str, Any] | None = None,
        correlation_result: Dict[str, Any] | None = None,
        investigation: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """
        Run complete risk analysis.
        """

        result = self.calculate_risk_score(
            detection=detection,
            threat_intelligence=(
                threat_intelligence
            ),
            anomaly_result=(
                anomaly_result
            ),
            correlation_result=(
                correlation_result
            ),
            investigation=(
                investigation
            )
        )

        result["explanation"] = (
            self.generate_explanation(
                result
            )
        )

        return result


# -------------------------------------------------------------
# GLOBAL INSTANCE
# -------------------------------------------------------------

risk_engine = RiskEngine()


# -------------------------------------------------------------
# HELPER FUNCTION
# -------------------------------------------------------------

def calculate_security_risk(
    detection: Dict[str, Any] | None = None,
    threat_intelligence: Dict[str, Any] | None = None,
    anomaly_result: Dict[str, Any] | None = None,
    correlation_result: Dict[str, Any] | None = None,
    investigation: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    """
    Convenience function for calculating security risk.
    """

    return risk_engine.analyze(
        detection=detection,
        threat_intelligence=threat_intelligence,
        anomaly_result=anomaly_result,
        correlation_result=correlation_result,
        investigation=investigation
    )