"""
CRUD Operations
---------------

CRUD = Create, Read, Update, Delete

This module contains database-style operations for security alerts.

Current version:
- Uses an in-memory list
- Keeps database logic separate from API routes
- Can later be replaced with SQLAlchemy database operations
"""

from typing import Any, Dict, List, Optional


class AlertCRUD:
    """
    CRUD operations for cybersecurity alerts.
    """

    def __init__(self):
        self.alerts: List[Dict[str, Any]] = []

    # ---------------------------------------------------------
    # CREATE
    # ---------------------------------------------------------

    def create_alert(
        self,
        alert: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create and store a new security alert.
        """

        self.alerts.append(alert)

        return alert

    # ---------------------------------------------------------
    # READ ALL
    # ---------------------------------------------------------

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """
        Return all stored security alerts.
        """

        return self.alerts

    # ---------------------------------------------------------
    # READ ONE
    # ---------------------------------------------------------

    def get_alert_by_id(
        self,
        alert_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Find an alert using its alert ID.
        """

        for alert in self.alerts:
            if alert.get("alert_id") == alert_id:
                return alert

        return None

    # ---------------------------------------------------------
    # UPDATE
    # ---------------------------------------------------------

    def update_alert(
        self,
        alert_id: str,
        updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Update an existing alert.

        Only fields provided inside `updates` are changed.
        """

        alert = self.get_alert_by_id(alert_id)

        if alert is None:
            return None

        alert.update(updates)

        return alert

    # ---------------------------------------------------------
    # DELETE
    # ---------------------------------------------------------

    def delete_alert(
        self,
        alert_id: str
    ) -> bool:
        """
        Delete an alert using its alert ID.

        Returns:
            True  -> alert deleted
            False -> alert not found
        """

        for index, alert in enumerate(self.alerts):

            if alert.get("alert_id") == alert_id:

                self.alerts.pop(index)

                return True

        return False

    # ---------------------------------------------------------
    # SEARCH
    # ---------------------------------------------------------

    def search_alerts(
        self,
        keyword: str
    ) -> List[Dict[str, Any]]:
        """
        Search alerts by source, event type, description,
        severity, or threat category.
        """

        keyword = keyword.lower().strip()

        if not keyword:
            return []

        results = []

        for alert in self.alerts:

            searchable_text = " ".join([
                str(alert.get("source", "")),
                str(alert.get("event_type", "")),
                str(alert.get("description", "")),
                str(alert.get("severity", "")),
                str(alert.get("threat_category", ""))
            ]).lower()

            if keyword in searchable_text:
                results.append(alert)

        return results

    # ---------------------------------------------------------
    # FILTER BY SEVERITY
    # ---------------------------------------------------------

    def get_alerts_by_severity(
        self,
        severity: str
    ) -> List[Dict[str, Any]]:
        """
        Return alerts matching a specific severity.
        """

        severity = severity.lower().strip()

        return [
            alert
            for alert in self.alerts
            if str(alert.get("severity", "")).lower() == severity
        ]

    # ---------------------------------------------------------
    # FILTER BY STATUS
    # ---------------------------------------------------------

    def get_alerts_by_status(
        self,
        status: str
    ) -> List[Dict[str, Any]]:
        """
        Return alerts matching a specific status.
        """

        status = status.lower().strip()

        return [
            alert
            for alert in self.alerts
            if str(alert.get("status", "")).lower() == status
        ]

    # ---------------------------------------------------------
    # FILTER BY THREAT CATEGORY
    # ---------------------------------------------------------

    def get_alerts_by_category(
        self,
        category: str
    ) -> List[Dict[str, Any]]:
        """
        Return alerts matching a threat category.
        """

        category = category.lower().strip()

        return [
            alert
            for alert in self.alerts
            if str(
                alert.get("threat_category", "")
            ).lower() == category
        ]

    # ---------------------------------------------------------
    # COUNT
    # ---------------------------------------------------------

    def count_alerts(self) -> int:
        """
        Return the total number of alerts.
        """

        return len(self.alerts)

    # ---------------------------------------------------------
    # STATISTICS
    # ---------------------------------------------------------

    def get_statistics(self) -> Dict[str, int]:
        """
        Generate basic SOC alert statistics.
        """

        statistics = {
            "total": len(self.alerts),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
            "pending": 0,
            "analyzed": 0
        }

        for alert in self.alerts:

            severity = str(
                alert.get("severity", "unknown")
            ).lower()

            status = str(
                alert.get("status", "")
            ).lower()

            if severity in statistics:
                statistics[severity] += 1

            if status in statistics:
                statistics[status] += 1

        return statistics

    # ---------------------------------------------------------
    # CLEAR DATABASE
    # ---------------------------------------------------------

    def clear_alerts(self) -> None:
        """
        Remove all alerts.

        Useful during development/testing.
        """

        self.alerts.clear()


# -------------------------------------------------------------
# GLOBAL CRUD INSTANCE
# -------------------------------------------------------------

alert_crud = AlertCRUD()