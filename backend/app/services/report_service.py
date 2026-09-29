"""
=========================================================
SENTRIX - AI CYBERSECURITY SOC PLATFORM
Report Generation Service
=========================================================

File:
    backend/app/services/report_service.py

Purpose:
    Generate, store, retrieve and delete SENTRIX
    security reports.

Supported report types:
    - Daily Security Summary
    - Threat Intelligence
    - AI Detection
    - Incident Investigation
    - Custom Security Report

Storage:
    backend/data/reports/

=========================================================
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import uuid


# =========================================================
# DIRECTORIES
# =========================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "data"

REPORTS_DIR = DATA_DIR / "reports"

REPORTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# =========================================================
# REPORT SERVICE
# =========================================================

class ReportService:
    """
    Handles SENTRIX security report operations.
    """

    def __init__(self) -> None:

        self.reports_dir = REPORTS_DIR

    # =====================================================
    # TIME
    # =====================================================

    @staticmethod
    def current_time() -> str:
        """
        Return current UTC timestamp.
        """

        return datetime.now(
            timezone.utc
        ).isoformat()

    # =====================================================
    # REPORT ID
    # =====================================================

    @staticmethod
    def generate_report_id() -> str:
        """
        Generate unique report ID.
        """

        return (
            f"RPT-"
            f"{datetime.now().strftime('%Y%m%d')}-"
            f"{uuid.uuid4().hex[:8].upper()}"
        )

    # =====================================================
    # FILE PATH
    # =====================================================

    def get_report_path(
        self,
        report_id: str
    ) -> Path:
        """
        Return JSON path for a report.
        """

        return self.reports_dir / f"{report_id}.json"

    # =====================================================
    # GENERATE REPORT
    # =====================================================

    def generate_report(
        self,
        report_type: str = "daily",
        title: Optional[str] = None,
        severity: str = "MEDIUM",
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a new security report.
        """

        report_type = (
            str(report_type)
            .strip()
            .lower()
        )

        severity = (
            str(severity)
            .strip()
            .upper()
        )

        report_id = self.generate_report_id()

        report_title = title or self.default_title(
            report_type
        )

        report = {
            "report_id": report_id,

            "title": report_title,

            "type": report_type.upper(),

            "severity": severity,

            "status": "READY",

            "description": (
                description
                or self.default_description(
                    report_type
                )
            ),

            "generated_by": "SENTRIX AI",

            "created_at": self.current_time(),

            "updated_at": self.current_time(),

            "summary": self.generate_summary(
                report_type
            ),

            "statistics": {
                "total_events": 12847,

                "critical_events": 2,

                "high_events": 5,

                "medium_events": 13,

                "low_events": 27,

                "blocked_threats": 342,

                "investigations": 8
            },

            "threats": [
                {
                    "threat_id": "THR-001",
                    "severity": "CRITICAL",
                    "type": "Suspicious Network Activity",
                    "status": "INVESTIGATING"
                },
                {
                    "threat_id": "THR-002",
                    "severity": "HIGH",
                    "type": "Malicious IP Activity",
                    "status": "BLOCKED"
                },
                {
                    "threat_id": "THR-003",
                    "severity": "MEDIUM",
                    "type": "Abnormal Login Pattern",
                    "status": "MONITORED"
                }
            ],

            "recommendations": [
                "Review critical security alerts.",
                "Investigate suspicious network activity.",
                "Monitor high-risk indicators.",
                "Keep detection rules and threat intelligence updated."
            ]
        }

        self.save_report(report)

        return report

    # =====================================================
    # DEFAULT TITLE
    # =====================================================

    @staticmethod
    def default_title(
        report_type: str
    ) -> str:

        titles = {
            "daily": "Daily Security Summary",

            "threat_intelligence":
                "Threat Intelligence Report",

            "detection":
                "AI Detection Report",

            "investigation":
                "Incident Investigation Report",

            "custom":
                "Custom Security Report"
        }

        return titles.get(
            report_type,
            "SENTRIX Security Report"
        )

    # =====================================================
    # DEFAULT DESCRIPTION
    # =====================================================

    @staticmethod
    def default_description(
        report_type: str
    ) -> str:

        descriptions = {
            "daily":
                "Summary of security activity detected by SENTRIX.",

            "threat_intelligence":
                "Analysis of indicators and threat intelligence activity.",

            "detection":
                "Summary of AI-based security event detection.",

            "investigation":
                "Summary of active and completed security investigations.",

            "custom":
                "Custom security report generated by SENTRIX."
        }

        return descriptions.get(
            report_type,
            "SENTRIX security analysis report."
        )

    # =====================================================
    # SUMMARY
    # =====================================================

    @staticmethod
    def generate_summary(
        report_type: str
    ) -> Dict[str, Any]:

        return {
            "security_score": 94,

            "system_status": "ONLINE",

            "risk_level": "MEDIUM",

            "analysis_engine": "SENTRIX AI",

            "report_type": report_type.upper()
        }

    # =====================================================
    # SAVE REPORT
    # =====================================================

    def save_report(
        self,
        report: Dict[str, Any]
    ) -> None:
        """
        Save report to JSON.
        """

        report_id = report["report_id"]

        path = self.get_report_path(
            report_id
        )

        with open(
            path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4
            )

    # =====================================================
    # GET REPORT
    # =====================================================

    def get_report(
        self,
        report_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve a report.
        """

        path = self.get_report_path(
            report_id
        )

        if not path.exists():
            return None

        try:

            with open(
                path,
                "r",
                encoding="utf-8"
            ) as file:

                return json.load(file)

        except (
            json.JSONDecodeError,
            OSError
        ):

            return None

    # =====================================================
    # GET ALL REPORTS
    # =====================================================

    def get_all_reports(self) -> List[Dict[str, Any]]:
        """
        Return all stored reports.
        """

        reports = []

        for path in self.reports_dir.glob(
            "*.json"
        ):

            try:

                with open(
                    path,
                    "r",
                    encoding="utf-8"
                ) as file:

                    report = json.load(file)

                    reports.append(report)

            except (
                json.JSONDecodeError,
                OSError
            ):

                continue

        reports.sort(
            key=lambda item: item.get(
                "created_at",
                ""
            ),
            reverse=True
        )

        return reports

    # =====================================================
    # DELETE REPORT
    # =====================================================

    def delete_report(
        self,
        report_id: str
    ) -> bool:
        """
        Delete a report.
        """

        path = self.get_report_path(
            report_id
        )

        if not path.exists():
            return False

        try:

            path.unlink()

            return True

        except OSError:

            return False

    # =====================================================
    # REPORT COUNT
    # =====================================================

    def report_count(self) -> int:
        """
        Return number of stored reports.
        """

        return len(
            list(
                self.reports_dir.glob("*.json")
            )
        )


# =========================================================
# SINGLETON
# =========================================================

report_service = ReportService()
