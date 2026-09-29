"""
Security Event Correlation Engine
---------------------------------

Correlates multiple security events to identify relationships
and possible attack sequences.

Correlation factors:

- Shared IP addresses
- Shared domains
- Shared URLs
- Shared file hashes
- Shared usernames
- Related event types
- Temporal proximity
- Attack-chain patterns

This is a rule-based correlation engine. It does not prove
that correlated events belong to the same attacker.
"""


from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional


class CorrelationEngine:
    """
    Correlates processed security events.
    """

    # ---------------------------------------------------------
    # CONFIGURATION
    # ---------------------------------------------------------

    DEFAULT_TIME_WINDOW_MINUTES = 15

    # Events that can form a possible attack chain.
    ATTACK_CHAIN = [
        "authentication_failure",
        "authentication_success",
        "powershell_activity",
        "malicious_download"
    ]

    RELATED_EVENTS = {
        "authentication_failure": {
            "authentication_success",
            "brute_force"
        },

        "authentication_success": {
            "powershell_activity",
            "malicious_download"
        },

        "network_scanning": {
            "sql_injection",
            "xss",
            "authentication_failure"
        },

        "powershell_activity": {
            "malicious_download",
            "malware"
        },

        "malicious_download": {
            "malware",
            "ransomware"
        }
    }

    # ---------------------------------------------------------
    # TIMESTAMP PARSER
    # ---------------------------------------------------------

    @staticmethod
    def parse_timestamp(
        timestamp: Any
    ) -> Optional[datetime]:
        """
        Convert a timestamp into a datetime object.
        """

        if timestamp is None:
            return None

        if isinstance(
            timestamp,
            datetime
        ):
            return timestamp

        try:
            value = str(timestamp)

            return datetime.fromisoformat(
                value.replace(
                    "Z",
                    "+00:00"
                )
            )

        except (
            ValueError,
            TypeError
        ):
            return None

    # ---------------------------------------------------------
    # EXTRACT IOCs
    # ---------------------------------------------------------

    @staticmethod
    def extract_iocs(
        log: Dict[str, Any]
    ) -> Dict[str, List[str]]:
        """
        Extract all observable indicators from a processed log.
        """

        iocs = log.get(
            "iocs",
            {}
        )

        hashes = iocs.get(
            "hashes",
            {}
        )

        return {
            "ip_addresses": iocs.get(
                "ip_addresses",
                []
            ),

            "domains": iocs.get(
                "domains",
                []
            ),

            "urls": iocs.get(
                "urls",
                []
            ),

            "hashes": (
                hashes.get("md5", [])
                + hashes.get("sha1", [])
                + hashes.get("sha256", [])
            )
        }

    # ---------------------------------------------------------
    # SHARED IOC DETECTION
    # ---------------------------------------------------------

    @classmethod
    def find_shared_iocs(
        cls,
        log_a: Dict[str, Any],
        log_b: Dict[str, Any]
    ) -> Dict[str, List[str]]:
        """
        Identify IOCs shared by two events.
        """

        iocs_a = cls.extract_iocs(
            log_a
        )

        iocs_b = cls.extract_iocs(
            log_b
        )

        shared = {}

        for ioc_type in iocs_a:

            intersection = sorted(
                set(iocs_a[ioc_type])
                & set(iocs_b[ioc_type])
            )

            if intersection:
                shared[ioc_type] = intersection

        return shared

    # ---------------------------------------------------------
    # SHARED USER
    # ---------------------------------------------------------

    @staticmethod
    def find_shared_user(
        log_a: Dict[str, Any],
        log_b: Dict[str, Any]
    ) -> Optional[str]:
        """
        Detect whether two events involve the same username.
        """

        user_fields = [
            "username",
            "user",
            "user_name",
            "account",
            "account_name"
        ]

        for field in user_fields:

            user_a = log_a.get(
                field
            )

            user_b = log_b.get(
                field
            )

            if (
                user_a
                and user_b
                and str(user_a).lower()
                == str(user_b).lower()
            ):
                return str(user_a)

        return None

    # ---------------------------------------------------------
    # TIME PROXIMITY
    # ---------------------------------------------------------

    @classmethod
    def check_time_proximity(
        cls,
        log_a: Dict[str, Any],
        log_b: Dict[str, Any],
        window_minutes: int
    ) -> Dict[str, Any]:
        """
        Determine whether two events occurred close together.
        """

        timestamp_a = cls.parse_timestamp(
            log_a.get("timestamp")
        )

        timestamp_b = cls.parse_timestamp(
            log_b.get("timestamp")
        )

        if not timestamp_a or not timestamp_b:
            return {
                "within_window": False,
                "time_difference_seconds": None
            }

        # Normalize timezone-naive timestamps if necessary.
        if (
            timestamp_a.tzinfo is None
            and timestamp_b.tzinfo is not None
        ):
            timestamp_b = timestamp_b.replace(
                tzinfo=None
            )

        elif (
            timestamp_b.tzinfo is None
            and timestamp_a.tzinfo is not None
        ):
            timestamp_a = timestamp_a.replace(
                tzinfo=None
            )

        difference = abs(
            (
                timestamp_a
                - timestamp_b
            ).total_seconds()
        )

        return {
            "within_window": (
                difference
                <= window_minutes * 60
            ),

            "time_difference_seconds": (
                round(
                    difference,
                    2
                )
            )
        }

    # ---------------------------------------------------------
    # EVENT RELATIONSHIP
    # ---------------------------------------------------------

    @classmethod
    def are_events_related(
        cls,
        event_type_a: str,
        event_type_b: str
    ) -> bool:
        """
        Determine whether two event types have a known
        security relationship.
        """

        if event_type_b in cls.RELATED_EVENTS.get(
            event_type_a,
            set()
        ):
            return True

        if event_type_a in cls.RELATED_EVENTS.get(
            event_type_b,
            set()
        ):
            return True

        return False

    # ---------------------------------------------------------
    # CORRELATION SCORE
    # ---------------------------------------------------------

    @classmethod
    def calculate_correlation_score(
        cls,
        shared_iocs: Dict[str, List[str]],
        shared_user: Optional[str],
        time_proximity: Dict[str, Any],
        related_event_types: bool
    ) -> int:
        """
        Calculate a correlation score from 0 to 100.
        """

        score = 0

        # Shared IP
        if shared_iocs.get(
            "ip_addresses"
        ):
            score += 35

        # Shared domain
        if shared_iocs.get(
            "domains"
        ):
            score += 20

        # Shared URL
        if shared_iocs.get(
            "urls"
        ):
            score += 20

        # Shared hash
        if shared_iocs.get(
            "hashes"
        ):
            score += 30

        # Shared user
        if shared_user:
            score += 25

        # Close timestamps
        if time_proximity.get(
            "within_window"
        ):
            score += 20

        # Known event relationship
        if related_event_types:
            score += 15

        return min(
            score,
            100
        )

    # ---------------------------------------------------------
    # CORRELATE TWO EVENTS
    # ---------------------------------------------------------

    @classmethod
    def correlate_pair(
        cls,
        log_a: Dict[str, Any],
        log_b: Dict[str, Any],
        window_minutes: int = DEFAULT_TIME_WINDOW_MINUTES
    ) -> Dict[str, Any]:
        """
        Correlate two security events.
        """

        event_type_a = log_a.get(
            "event_type",
            "unknown"
        )

        event_type_b = log_b.get(
            "event_type",
            "unknown"
        )

        shared_iocs = cls.find_shared_iocs(
            log_a,
            log_b
        )

        shared_user = cls.find_shared_user(
            log_a,
            log_b
        )

        time_proximity = cls.check_time_proximity(
            log_a,
            log_b,
            window_minutes
        )

        related_events = cls.are_events_related(
            event_type_a,
            event_type_b
        )

        score = cls.calculate_correlation_score(
            shared_iocs,
            shared_user,
            time_proximity,
            related_events
        )

        correlated = score >= 30

        return {
            "correlated": correlated,

            "correlation_score": score,

            "event_1": {
                "event_type": event_type_a,
                "timestamp": log_a.get(
                    "timestamp"
                )
            },

            "event_2": {
                "event_type": event_type_b,
                "timestamp": log_b.get(
                    "timestamp"
                )
            },

            "shared_iocs": shared_iocs,

            "shared_user": shared_user,

            "time_proximity": time_proximity,

            "related_event_types": related_events
        }

    # ---------------------------------------------------------
    # CORRELATE ALL EVENTS
    # ---------------------------------------------------------

    @classmethod
    def correlate_events(
        cls,
        logs: List[Dict[str, Any]],
        window_minutes: int = DEFAULT_TIME_WINDOW_MINUTES
    ) -> List[Dict[str, Any]]:
        """
        Compare all event pairs and return correlated events.
        """

        correlations = []

        for i in range(
            len(logs)
        ):

            for j in range(
                i + 1,
                len(logs)
            ):

                result = cls.correlate_pair(
                    logs[i],
                    logs[j],
                    window_minutes
                )

                if result["correlated"]:

                    result["event_1_index"] = i
                    result["event_2_index"] = j

                    correlations.append(
                        result
                    )

        return correlations

    # ---------------------------------------------------------
    # GROUP EVENTS BY IOC
    # ---------------------------------------------------------

    @classmethod
    def group_by_ioc(
        cls,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, List[int]]:
        """
        Group event indexes by shared IOC.
        """

        ioc_groups = defaultdict(
            list
        )

        for index, log in enumerate(
            logs
        ):

            iocs = cls.extract_iocs(
                log
            )

            for ioc_list in iocs.values():

                for ioc in ioc_list:

                    if index not in ioc_groups[ioc]:
                        ioc_groups[ioc].append(
                            index
                        )

        return dict(
            ioc_groups
        )

    # ---------------------------------------------------------
    # DETECT ATTACK CHAINS
    # ---------------------------------------------------------

    @classmethod
    def detect_attack_chains(
        cls,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect possible multi-stage attack sequences.
        """

        event_positions = defaultdict(
            list
        )

        for index, log in enumerate(
            logs
        ):

            event_type = log.get(
                "event_type",
                "unknown"
            )

            event_positions[
                event_type
            ].append(index)

        chains = []

        for index in event_positions.get(
            "authentication_failure",
            []
        ):

            success_positions = [
                position
                for position in event_positions.get(
                    "authentication_success",
                    []
                )
                if position > index
            ]

            if not success_positions:
                continue

            success_index = (
                success_positions[0]
            )

            powershell_positions = [
                position
                for position in event_positions.get(
                    "powershell_activity",
                    []
                )
                if position > success_index
            ]

            if not powershell_positions:
                continue

            powershell_index = (
                powershell_positions[0]
            )

            download_positions = [
                position
                for position in event_positions.get(
                    "malicious_download",
                    []
                )
                if position > powershell_index
            ]

            chain = {
                "chain_type": (
                    "possible_compromise_sequence"
                ),

                "events": [
                    {
                        "index": index,
                        "event_type": (
                            "authentication_failure"
                        )
                    },
                    {
                        "index": success_index,
                        "event_type": (
                            "authentication_success"
                        )
                    },
                    {
                        "index": powershell_index,
                        "event_type": (
                            "powershell_activity"
                        )
                    }
                ],

                "confidence": "medium"
            }

            if download_positions:

                chain["events"].append({
                    "index": download_positions[0],
                    "event_type": (
                        "malicious_download"
                    )
                })

                chain["confidence"] = "high"

            chains.append(
                chain
            )

        return chains

    # ---------------------------------------------------------
    # CORRELATION SUMMARY
    # ---------------------------------------------------------

    @staticmethod
    def generate_summary(
        correlations: List[Dict[str, Any]],
        attack_chains: List[Dict[str, Any]]
    ) -> str:
        """
        Generate a human-readable correlation summary.
        """

        if not correlations and not attack_chains:

            return (
                "No significant relationships were identified "
                "between the analyzed security events."
            )

        parts = []

        if correlations:

            parts.append(
                f"{len(correlations)} correlated event "
                f"relationship(s) were identified."
            )

        if attack_chains:

            parts.append(
                f"{len(attack_chains)} possible multi-stage "
                f"attack sequence(s) were identified."
            )

        return " ".join(parts)

    # ---------------------------------------------------------
    # COMPLETE ANALYSIS
    # ---------------------------------------------------------

    def analyze(
        self,
        logs: List[Dict[str, Any]],
        window_minutes: int = DEFAULT_TIME_WINDOW_MINUTES
    ) -> Dict[str, Any]:
        """
        Run the complete correlation engine.
        """

        if not logs:

            return {
                "status": "no_data",
                "logs_analyzed": 0,
                "correlations": [],
                "attack_chains": [],
                "summary": (
                    "No logs were provided for correlation."
                )
            }

        correlations = self.correlate_events(
            logs,
            window_minutes
        )

        attack_chains = self.detect_attack_chains(
            logs
        )

        ioc_groups = self.group_by_ioc(
            logs
        )

        return {
            "status": "analyzed",

            "logs_analyzed": len(
                logs
            ),

            "correlation_count": len(
                correlations
            ),

            "attack_chain_count": len(
                attack_chains
            ),

            "correlations": correlations,

            "attack_chains": attack_chains,

            "ioc_groups": ioc_groups,

            "summary": self.generate_summary(
                correlations,
                attack_chains
            )
        }


# -------------------------------------------------------------
# GLOBAL INSTANCE
# -------------------------------------------------------------

correlation_engine = CorrelationEngine()


# -------------------------------------------------------------
# HELPER FUNCTION
# -------------------------------------------------------------

def correlate_security_events(
    logs: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Convenience function for event correlation.
    """

    return correlation_engine.analyze(
        logs
    )