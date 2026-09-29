"""
SOC Orchestrator
----------------

Central coordinator for the AI Cybersecurity SOC Analyst.

Pipeline:

Raw Log
   ↓
Log Processor
   ↓
Threat Intelligence
   ↓
MITRE ATT&CK
   ↓
Detection Agent
   ↓
Hunter Agent
   ↓
Investigator Agent
   ↓
AI Analysis
   ↓
Final SOC Report

The orchestrator coordinates the components but keeps the
actual security logic inside the respective services/agents.
"""

from typing import Any, Dict, List

from app.services.log_processor import LogProcessor
from app.services.threat_intel import ThreatIntelService
from app.services.mitre_service import MitreService

from app.agents.detection_agent import DetectionAgent
from app.agents.hunter_agent import HunterAgent
from app.agents.investigator_agent import InvestigatorAgent


class SOCOrchestrator:
    """
    Central orchestration engine for the SOC Analyst.
    """

    # ---------------------------------------------------------
    # INITIALIZATION
    # ---------------------------------------------------------

    def __init__(self) -> None:
        self.log_processor = LogProcessor
        self.threat_intel = ThreatIntelService
        self.mitre_service = MitreService
        self.detection_agent = DetectionAgent
        self.hunter_agent = HunterAgent
        self.investigator_agent = InvestigatorAgent

    # ---------------------------------------------------------
    # PROCESS SINGLE LOG
    # ---------------------------------------------------------

    def process_log(
        self,
        log_text: str
    ) -> Dict[str, Any]:
        """
        Process a single raw security log through the SOC pipeline.
        """

        if not log_text or not log_text.strip():
            raise ValueError(
                "Log text cannot be empty."
            )

        # -----------------------------------------------------
        # STEP 1: LOG PROCESSING
        # -----------------------------------------------------

        processed_log = self.log_processor.process_log(
            log_text
        )

        # -----------------------------------------------------
        # STEP 2: THREAT INTELLIGENCE
        # -----------------------------------------------------

        processed_log = (
            self.threat_intel.analyze_processed_log(
                processed_log
            )
        )

        # -----------------------------------------------------
        # STEP 3: MITRE ATT&CK
        # -----------------------------------------------------

        processed_log = (
            self.mitre_service.analyze_log(
                processed_log
            )
        )

        # -----------------------------------------------------
        # STEP 4: DETECTION
        # -----------------------------------------------------

        detection_result = (
            self.detection_agent.detect(
                processed_log
            )
        )

        # -----------------------------------------------------
        # FINAL RESULT
        # -----------------------------------------------------

        return {
            "status": "processed",
            "log": processed_log,
            "detection": detection_result
        }

    # ---------------------------------------------------------
    # PROCESS MULTIPLE LOGS
    # ---------------------------------------------------------

    def process_logs(
        self,
        logs: List[str]
    ) -> Dict[str, Any]:
        """
        Process multiple raw security logs.

        The logs are first normalized individually and then
        analyzed together by the Hunter and Investigator agents.
        """

        if not logs:
            return {
                "status": "no_data",
                "logs_processed": 0,
                "results": []
            }

        processed_logs: List[Dict[str, Any]] = []
        detection_results: List[Dict[str, Any]] = []

        # -----------------------------------------------------
        # STEP 1-4: PROCESS EACH LOG
        # -----------------------------------------------------

        for log_text in logs:

            if not log_text or not log_text.strip():
                continue

            try:
                result = self.process_log(
                    log_text
                )

                processed_logs.append(
                    result["log"]
                )

                detection_results.append(
                    result["detection"]
                )

            except ValueError:
                continue

        if not processed_logs:
            return {
                "status": "no_valid_logs",
                "logs_processed": 0,
                "results": []
            }

        # -----------------------------------------------------
        # STEP 5: THREAT HUNTING
        # -----------------------------------------------------

        hunting_result = (
            self.hunter_agent.hunt(
                processed_logs
            )
        )

        # -----------------------------------------------------
        # STEP 6: INVESTIGATION
        # -----------------------------------------------------

        # Use the highest-risk detection result as the
        # primary investigation context.
        primary_detection = (
            self._select_primary_detection(
                detection_results
            )
        )

        investigation_result = (
            self.investigator_agent.investigate(
                processed_logs,
                primary_detection,
                hunting_result
            )
        )

        # -----------------------------------------------------
        # STEP 7: SUMMARY
        # -----------------------------------------------------

        overall_risk = self._calculate_overall_risk(
            detection_results,
            hunting_result
        )

        return {
            "status": "processed",
            "logs_processed": len(processed_logs),

            "overall_risk": overall_risk,

            "logs": processed_logs,

            "detections": detection_results,

            "threat_hunting": hunting_result,

            "investigation": investigation_result
        }

    # ---------------------------------------------------------
    # PRIMARY DETECTION
    # ---------------------------------------------------------

    @staticmethod
    def _select_primary_detection(
        detection_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Select the highest-risk detection result.

        This is used as the primary context for investigation.
        """

        if not detection_results:
            return {}

        return max(
            detection_results,
            key=lambda result: result.get(
                "risk_score",
                0
            )
        )

    # ---------------------------------------------------------
    # OVERALL RISK
    # ---------------------------------------------------------

    @staticmethod
    def _calculate_overall_risk(
        detection_results: List[Dict[str, Any]],
        hunting_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate an overall SOC risk level.
        """

        detection_scores = [
            result.get(
                "risk_score",
                0
            )
            for result in detection_results
        ]

        highest_detection_score = (
            max(detection_scores)
            if detection_scores
            else 0
        )

        hunting_status = hunting_result.get(
            "overall_status",
            "no_significant_findings"
        )

        # -----------------------------------------------------
        # Determine overall level
        # -----------------------------------------------------

        if (
            highest_detection_score >= 80
            or hunting_status == "critical"
        ):
            level = "critical"

        elif (
            highest_detection_score >= 60
            or hunting_status == "high"
        ):
            level = "high"

        elif (
            highest_detection_score >= 30
            or hunting_status == "suspicious"
        ):
            level = "medium"

        elif highest_detection_score > 0:
            level = "low"

        else:
            level = "informational"

        return {
            "risk_score": highest_detection_score,
            "risk_level": level,
            "detection_count": len(
                detection_results
            ),
            "hunting_status": hunting_status
        }

    # ---------------------------------------------------------
    # COMPLETE SOC ANALYSIS
    # ---------------------------------------------------------

    def analyze(
        self,
        logs: List[str]
    ) -> Dict[str, Any]:
        """
        Run the complete SOC analysis pipeline.

        This is the main entry point that can later be called
        from FastAPI routes.
        """

        return self.process_logs(
            logs
        )


# -------------------------------------------------------------
# GLOBAL ORCHESTRATOR INSTANCE
# -------------------------------------------------------------

soc_orchestrator = SOCOrchestrator()


# -------------------------------------------------------------
# HELPER FUNCTION
# -------------------------------------------------------------

def analyze_security_logs(
    logs: List[str]
) -> Dict[str, Any]:
    """
    Convenience function for running the SOC pipeline.
    """

    return soc_orchestrator.analyze(
        logs
    )