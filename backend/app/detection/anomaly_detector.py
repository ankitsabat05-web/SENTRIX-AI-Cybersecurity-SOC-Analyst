"""
Anomaly Detector
----------------

Detects unusual behavior in security logs using lightweight
statistical and rule-based techniques.

This module looks for:

- Unusual event frequency
- Repeated authentication failures
- Unusual source IP activity
- Rare event types
- Suspicious time patterns
- Sudden spikes in activity
- Unusual IOC frequency

This is a baseline anomaly detector. It is not a machine
learning model and should not be treated as proof of compromise.
"""

from collections import Counter
from datetime import datetime
from typing import Any, Dict, List


class AnomalyDetector:
    """
    Detects anomalous patterns in processed security logs.
    """

    # ---------------------------------------------------------
    # THRESHOLDS
    # ---------------------------------------------------------

    EVENT_SPIKE_THRESHOLD = 10

    SOURCE_IP_THRESHOLD = 5

    FAILED_LOGIN_THRESHOLD = 5

    IOC_REPEAT_THRESHOLD = 5

    RARE_EVENT_THRESHOLD = 1

    # ---------------------------------------------------------
    # INITIALIZATION
    # ---------------------------------------------------------

    def __init__(self) -> None:
        self.event_counts: Counter = Counter()
        self.source_ip_counts: Counter = Counter()

    # ---------------------------------------------------------
    # EVENT FREQUENCY
    # ---------------------------------------------------------

    @staticmethod
    def count_event_types(
        logs: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """
        Count how frequently each event type occurs.
        """

        counter = Counter()

        for log in logs:

            event_type = log.get(
                "event_type",
                "unknown"
            )

            counter[event_type] += 1

        return dict(counter)

    # ---------------------------------------------------------
    # SOURCE IP FREQUENCY
    # ---------------------------------------------------------

    @staticmethod
    def count_source_ips(
        logs: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """
        Count occurrences of source IP addresses.
        """

        counter = Counter()

        for log in logs:

            iocs = log.get(
                "iocs",
                {}
            )

            ip_addresses = iocs.get(
                "ip_addresses",
                []
            )

            for ip in ip_addresses:
                counter[ip] += 1

        return dict(counter)

    # ---------------------------------------------------------
    # IOC FREQUENCY
    # ---------------------------------------------------------

    @staticmethod
    def count_iocs(
        logs: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """
        Count how frequently individual IOCs appear.
        """

        counter = Counter()

        for log in logs:

            iocs = log.get(
                "iocs",
                {}
            )

            for ip in iocs.get(
                "ip_addresses",
                []
            ):
                counter[ip] += 1

            for domain in iocs.get(
                "domains",
                []
            ):
                counter[domain] += 1

            for url in iocs.get(
                "urls",
                []
            ):
                counter[url] += 1

            hashes = iocs.get(
                "hashes",
                {}
            )

            for hash_value in hashes.get(
                "md5",
                []
            ):
                counter[hash_value] += 1

            for hash_value in hashes.get(
                "sha1",
                []
            ):
                counter[hash_value] += 1

            for hash_value in hashes.get(
                "sha256",
                []
            ):
                counter[hash_value] += 1

        return dict(counter)

    # ---------------------------------------------------------
    # EVENT SPIKE DETECTION
    # ---------------------------------------------------------

    def detect_event_spikes(
        self,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect event types occurring unusually frequently.
        """

        event_counts = self.count_event_types(
            logs
        )

        anomalies = []

        for event_type, count in event_counts.items():

            if count >= self.EVENT_SPIKE_THRESHOLD:

                anomalies.append({
                    "anomaly_type": "event_frequency_spike",

                    "event_type": event_type,

                    "count": count,

                    "threshold": self.EVENT_SPIKE_THRESHOLD,

                    "severity": (
                        "high"
                        if count >= self.EVENT_SPIKE_THRESHOLD * 2
                        else "medium"
                    ),

                    "description": (
                        f"Event type '{event_type}' "
                        f"occurred {count} times, which is above "
                        "the configured frequency threshold."
                    )
                })

        return anomalies

    # ---------------------------------------------------------
    # FAILED LOGIN ANOMALY
    # ---------------------------------------------------------

    def detect_failed_login_anomalies(
        self,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect repeated authentication failures.
        """

        counter = Counter()

        for log in logs:

            event_type = log.get(
                "event_type",
                "unknown"
            )

            if event_type in {
                "authentication_failure",
                "brute_force"
            }:

                iocs = log.get(
                    "iocs",
                    {}
                )

                ips = iocs.get(
                    "ip_addresses",
                    []
                )

                if ips:

                    for ip in ips:
                        counter[ip] += 1

                else:

                    counter["unknown_source"] += 1

        anomalies = []

        for source, count in counter.items():

            if count >= self.FAILED_LOGIN_THRESHOLD:

                anomalies.append({
                    "anomaly_type": "authentication_spike",

                    "source": source,

                    "count": count,

                    "threshold": self.FAILED_LOGIN_THRESHOLD,

                    "severity": "high",

                    "description": (
                        f"{count} authentication failures "
                        f"were associated with source '{source}'."
                    )
                })

        return anomalies

    # ---------------------------------------------------------
    # SOURCE IP ANOMALY
    # ---------------------------------------------------------

    def detect_source_ip_anomalies(
        self,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect source IP addresses generating unusually
        large amounts of activity.
        """

        ip_counts = self.count_source_ips(
            logs
        )

        anomalies = []

        for ip, count in ip_counts.items():

            if count >= self.SOURCE_IP_THRESHOLD:

                anomalies.append({
                    "anomaly_type": "source_ip_activity",

                    "source_ip": ip,

                    "event_count": count,

                    "threshold": self.SOURCE_IP_THRESHOLD,

                    "severity": (
                        "high"
                        if count >= self.SOURCE_IP_THRESHOLD * 2
                        else "medium"
                    ),

                    "description": (
                        f"Source IP {ip} generated "
                        f"{count} observed events."
                    )
                })

        return anomalies

    # ---------------------------------------------------------
    # IOC REPETITION
    # ---------------------------------------------------------

    def detect_repeated_iocs(
        self,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect IOCs appearing repeatedly across logs.
        """

        ioc_counts = self.count_iocs(
            logs
        )

        anomalies = []

        for ioc, count in ioc_counts.items():

            if count >= self.IOC_REPEAT_THRESHOLD:

                anomalies.append({
                    "anomaly_type": "repeated_ioc",

                    "ioc": ioc,

                    "count": count,

                    "threshold": self.IOC_REPEAT_THRESHOLD,

                    "severity": "medium",

                    "description": (
                        f"IOC '{ioc}' appeared "
                        f"{count} times across the analyzed logs."
                    )
                })

        return anomalies

    # ---------------------------------------------------------
    # RARE EVENT DETECTION
    # ---------------------------------------------------------

    def detect_rare_events(
        self,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect event types that occur only once.

        A rare event is not automatically malicious. It is
        simply useful for analyst investigation.
        """

        event_counts = self.count_event_types(
            logs
        )

        anomalies = []

        for event_type, count in event_counts.items():

            if (
                count <= self.RARE_EVENT_THRESHOLD
                and event_type != "unknown"
            ):

                anomalies.append({
                    "anomaly_type": "rare_event",

                    "event_type": event_type,

                    "count": count,

                    "severity": "low",

                    "description": (
                        f"Event type '{event_type}' "
                        "occurred rarely in the analyzed dataset."
                    )
                })

        return anomalies

    # ---------------------------------------------------------
    # SUSPICIOUS TIME DETECTION
    # ---------------------------------------------------------

    @staticmethod
    def detect_unusual_time(
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect events occurring during unusual hours.

        Current baseline:
        00:00 - 05:00 is considered an unusual activity window.

        This is only a heuristic and should be replaced by a
        user/entity-specific baseline in a production system.
        """

        anomalies = []

        for log in logs:

            timestamp = log.get(
                "timestamp"
            )

            if not timestamp:
                continue

            try:
                display_timestamp = ""

                if isinstance(
                    timestamp,
                    datetime
                ):
                    dt = timestamp
                    display_timestamp = timestamp.isoformat()

                else:
                    timestamp_string = str(
                        timestamp
                    )
                    display_timestamp = timestamp_string

                    dt = datetime.fromisoformat(
                        timestamp_string.replace(
                            "Z",
                            "+00:00"
                        )
                    )

                if 0 <= dt.hour < 5:

                    anomalies.append({
                        "anomaly_type": "unusual_time",

                        "timestamp": display_timestamp,

                        "event_type": log.get(
                            "event_type",
                            "unknown"
                        ),

                        "severity": "low",

                        "description": (
                            "Security activity was observed "
                            "during the configured unusual "
                            "activity window."
                        )
                    })

            except (
                ValueError,
                TypeError
            ):
                continue

        return anomalies

    # ---------------------------------------------------------
    # ANOMALY SCORE
    # ---------------------------------------------------------

    @staticmethod
    def calculate_anomaly_score(
        anomalies: List[Dict[str, Any]]
    ) -> int:
        """
        Calculate an overall anomaly score from 0 to 100.
        """

        if not anomalies:
            return 0

        score = 0

        severity_weights = {
            "critical": 30,
            "high": 20,
            "medium": 10,
            "low": 5
        }

        for anomaly in anomalies:

            severity = anomaly.get(
                "severity",
                "low"
            )

            score += severity_weights.get(
                severity,
                0
            )

        return min(
            score,
            100
        )

    # ---------------------------------------------------------
    # ANOMALY LEVEL
    # ---------------------------------------------------------

    @staticmethod
    def classify_anomaly_score(
        score: int
    ) -> str:
        """
        Convert anomaly score to a severity level.
        """

        if score >= 80:
            return "critical"

        if score >= 60:
            return "high"

        if score >= 30:
            return "medium"

        if score > 0:
            return "low"

        return "normal"

    # ---------------------------------------------------------
    # MAIN ANALYSIS
    # ---------------------------------------------------------

    def analyze(
        self,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Run all anomaly detection techniques.
        """

        if not logs:

            return {
                "status": "no_data",

                "logs_analyzed": 0,

                "anomaly_score": 0,

                "anomaly_level": "normal",

                "anomaly_count": 0,

                "anomalies": []
            }

        anomalies: List[
            Dict[str, Any]
        ] = []

        # Event frequency
        anomalies.extend(
            self.detect_event_spikes(
                logs
            )
        )

        # Authentication anomalies
        anomalies.extend(
            self.detect_failed_login_anomalies(
                logs
            )
        )

        # Source IP anomalies
        anomalies.extend(
            self.detect_source_ip_anomalies(
                logs
            )
        )

        # Repeated IOC anomalies
        anomalies.extend(
            self.detect_repeated_iocs(
                logs
            )
        )

        # Rare events
        anomalies.extend(
            self.detect_rare_events(
                logs
            )
        )

        # Unusual time
        anomalies.extend(
            self.detect_unusual_time(
                logs
            )
        )

        anomaly_score = (
            self.calculate_anomaly_score(
                anomalies
            )
        )

        anomaly_level = (
            self.classify_anomaly_score(
                anomaly_score
            )
        )

        return {
            "status": "analyzed",

            "logs_analyzed": len(
                logs
            ),

            "anomaly_score": anomaly_score,

            "anomaly_level": anomaly_level,

            "anomaly_count": len(
                anomalies
            ),

            "anomalies": anomalies
        }


# -------------------------------------------------------------
# GLOBAL INSTANCE
# -------------------------------------------------------------

anomaly_detector = AnomalyDetector()


# -------------------------------------------------------------
# HELPER FUNCTION
# -------------------------------------------------------------

def detect_anomalies(
    logs: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Convenience function for anomaly detection.
    """

    return anomaly_detector.analyze(
        logs
    )