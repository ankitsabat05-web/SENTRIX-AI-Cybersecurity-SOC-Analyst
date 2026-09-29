"""
Investigator Agent
------------------

Responsible for investigating suspicious security alerts.

The Investigator Agent:
- Collects evidence from processed logs
- Correlates related events
- Builds an investigation timeline
- Identifies affected IPs, domains, URLs and hashes
- Reviews detection findings
- Reviews threat-hunting findings
- Reviews MITRE ATT&CK mappings
- Determines possible attack stages
- Generates an investigation summary

This agent does not automatically modify or isolate systems.
It produces investigation findings for the SOC analyst.
"""

from collections import defaultdict
from typing import Any, Dict, List, Set


class InvestigatorAgent:
    """
    Investigation engine for the AI Cybersecurity SOC Analyst.
    """

    # ---------------------------------------------------------
    # ATTACK STAGES
    # ---------------------------------------------------------

    ATTACK_STAGES = {
        "authentication_failure": "Initial Access / Credential Access",
        "brute_force": "Credential Access",
        "authentication_success": "Initial Access",
        "network_scanning": "Discovery",
        "powershell_activity": "Execution",
        "command_execution": "Execution",
        "malicious_download": "Command and Control",
        "malware": "Execution",
        "ransomware": "Impact",
        "sql_injection": "Initial Access",
        "xss": "Initial Access",
        "dos_attack": "Impact"
    }

    # ---------------------------------------------------------
    # EVIDENCE EXTRACTION
    # ---------------------------------------------------------

    @staticmethod
    def collect_evidence(
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Extract useful evidence from processed security logs.
        """

        ip_addresses: Set[str] = set()
        domains: Set[str] = set()
        urls: Set[str] = set()

        md5_hashes: Set[str] = set()
        sha1_hashes: Set[str] = set()
        sha256_hashes: Set[str] = set()

        event_types: Set[str] = set()
        log_sources: Set[str] = set()

        for log in logs:

            event_type = log.get(
                "event_type"
            )

            if event_type:
                event_types.add(event_type)

            log_source = log.get(
                "log_source"
            )

            if log_source:
                log_sources.add(log_source)

            iocs = log.get(
                "iocs",
                {}
            )

            ip_addresses.update(
                iocs.get(
                    "ip_addresses",
                    []
                )
            )

            domains.update(
                iocs.get(
                    "domains",
                    []
                )
            )

            urls.update(
                iocs.get(
                    "urls",
                    []
                )
            )

            hashes = iocs.get(
                "hashes",
                {}
            )

            md5_hashes.update(
                hashes.get(
                    "md5",
                    []
                )
            )

            sha1_hashes.update(
                hashes.get(
                    "sha1",
                    []
                )
            )

            sha256_hashes.update(
                hashes.get(
                    "sha256",
                    []
                )
            )

        return {
            "ip_addresses": sorted(ip_addresses),
            "domains": sorted(domains),
            "urls": sorted(urls),
            "hashes": {
                "md5": sorted(md5_hashes),
                "sha1": sorted(sha1_hashes),
                "sha256": sorted(sha256_hashes)
            },
            "event_types": sorted(event_types),
            "log_sources": sorted(log_sources)
        }

    # ---------------------------------------------------------
    # TIMELINE
    # ---------------------------------------------------------

    @staticmethod
    def build_timeline(
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Build a chronological investigation timeline.

        Logs without a timestamp are placed after
        timestamped events.
        """

        timeline = []

        for index, log in enumerate(logs):

            timeline.append({
                "sequence": index + 1,
                "timestamp": log.get(
                    "timestamp",
                    "unknown"
                ),
                "event_type": log.get(
                    "event_type",
                    "unknown"
                ),
                "severity": log.get(
                    "severity",
                    "unknown"
                ),
                "source": log.get(
                    "log_source",
                    "unknown"
                ),
                "description": log.get(
                    "summary",
                    log.get(
                        "cleaned_log",
                        ""
                    )
                )
            })

        timeline.sort(
            key=lambda event: (
                event["timestamp"] == "unknown",
                event["timestamp"]
            )
        )

        return timeline

    # ---------------------------------------------------------
    # EVENT CORRELATION
    # ---------------------------------------------------------

    @classmethod
    def correlate_events(
        cls,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Identify events that share the same IOC.

        Events are correlated when they contain the same
        IP address, domain, URL or file hash.
        """

        ioc_events = defaultdict(list)

        for index, log in enumerate(logs):

            iocs = log.get(
                "iocs",
                {}
            )

            indicators = []

            indicators.extend(
                iocs.get(
                    "ip_addresses",
                    []
                )
            )

            indicators.extend(
                iocs.get(
                    "domains",
                    []
                )
            )

            indicators.extend(
                iocs.get(
                    "urls",
                    []
                )
            )

            hashes = iocs.get(
                "hashes",
                {}
            )

            indicators.extend(
                hashes.get(
                    "md5",
                    []
                )
            )

            indicators.extend(
                hashes.get(
                    "sha1",
                    []
                )
            )

            indicators.extend(
                hashes.get(
                    "sha256",
                    []
                )
            )

            for indicator in indicators:
                ioc_events[indicator].append(
                    index
                )

        correlations = []

        for indicator, event_indexes in ioc_events.items():

            if len(event_indexes) < 2:
                continue

            correlations.append({
                "indicator": indicator,
                "event_count": len(event_indexes),
                "event_indexes": event_indexes,
                "relationship": (
                    "Multiple security events share "
                    "the same indicator."
                )
            })

        return correlations

    # ---------------------------------------------------------
    # ATTACK STAGE ANALYSIS
    # ---------------------------------------------------------

    @classmethod
    def identify_attack_stages(
        cls,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """
        Map observed event types to possible attack stages.
        """

        stages = []

        seen = set()

        for log in logs:

            event_type = log.get(
                "event_type",
                "unknown"
            )

            stage = cls.ATTACK_STAGES.get(
                event_type
            )

            if not stage:
                continue

            key = (
                event_type,
                stage
            )

            if key in seen:
                continue

            seen.add(key)

            stages.append({
                "event_type": event_type,
                "attack_stage": stage
            })

        return stages

    # ---------------------------------------------------------
    # DETECTION FINDING ANALYSIS
    # ---------------------------------------------------------

    @staticmethod
    def analyze_detection(
        detection_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extract important information from DetectionAgent.
        """

        if not detection_result:
            return {
                "detected": False,
                "risk_score": 0,
                "risk_level": "unknown",
                "reasons": []
            }

        return {
            "detected": detection_result.get(
                "detected",
                False
            ),
            "risk_score": detection_result.get(
                "risk_score",
                0
            ),
            "risk_level": detection_result.get(
                "risk_level",
                "unknown"
            ),
            "reasons": detection_result.get(
                "reasons",
                []
            )
        }

    # ---------------------------------------------------------
    # THREAT HUNTING ANALYSIS
    # ---------------------------------------------------------

    @staticmethod
    def analyze_hunting(
        hunting_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extract important information from HunterAgent.
        """

        if not hunting_result:
            return {
                "findings_count": 0,
                "overall_status": "unknown",
                "findings": []
            }

        return {
            "findings_count": hunting_result.get(
                "findings_count",
                0
            ),
            "overall_status": hunting_result.get(
                "overall_status",
                "unknown"
            ),
            "severity_counts": hunting_result.get(
                "severity_counts",
                {}
            ),
            "findings": hunting_result.get(
                "findings",
                []
            )
        }

    # ---------------------------------------------------------
    # MITRE ANALYSIS
    # ---------------------------------------------------------

    @staticmethod
    def analyze_mitre(
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Collect unique MITRE ATT&CK techniques
        observed across the investigation.
        """

        techniques = {}
        
        for log in logs:

            mitre_data = log.get(
                "mitre_attack",
                []
            )

            if not isinstance(
                mitre_data,
                list
            ):
                continue

            for technique in mitre_data:

                if not isinstance(
                    technique,
                    dict
                ):
                    continue

                technique_id = technique.get(
                    "technique_id"
                )

                if technique_id:
                    techniques[
                        technique_id
                    ] = technique

        return list(
            techniques.values()
        )

    # ---------------------------------------------------------
    # AFFECTED ASSET IDENTIFICATION
    # ---------------------------------------------------------

    @staticmethod
    def identify_affected_assets(
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Identify systems/assets represented in the logs.

        The current version uses available IOC and source
        information. Host-specific fields can be added later.
        """

        source_ips: Set[str] = set()
        domains: Set[str] = set()
        log_sources: Set[str] = set()

        for log in logs:

            iocs = log.get(
                "iocs",
                {}
            )

            source_ips.update(
                iocs.get(
                    "ip_addresses",
                    []
                )
            )

            domains.update(
                iocs.get(
                    "domains",
                    []
                )
            )

            source = log.get(
                "log_source"
            )

            if source:
                log_sources.add(source)

        return {
            "source_ips": sorted(source_ips),
            "domains": sorted(domains),
            "log_sources": sorted(log_sources)
        }

    # ---------------------------------------------------------
    # INVESTIGATION SEVERITY
    # ---------------------------------------------------------

    @staticmethod
    def determine_investigation_level(
        detection_result: Dict[str, Any],
        hunting_result: Dict[str, Any]
    ) -> str:
        """
        Determine the overall investigation level.
        """

        detection_level = detection_result.get(
            "risk_level",
            "unknown"
        )

        hunting_level = hunting_result.get(
            "overall_status",
            "unknown"
        )

        if (
            detection_level == "critical"
            or hunting_level == "critical"
        ):
            return "critical"

        if (
            detection_level == "high"
            or hunting_level == "high"
        ):
            return "high"

        if (
            detection_level == "medium"
            or hunting_level == "suspicious"
        ):
            return "medium"

        if (
            detection_level == "low"
        ):
            return "low"

        return "informational"

    # ---------------------------------------------------------
    # INVESTIGATION SUMMARY
    # ---------------------------------------------------------

    @classmethod
    def generate_summary(
        cls,
        logs: List[Dict[str, Any]],
        detection_result: Dict[str, Any],
        hunting_result: Dict[str, Any],
        evidence: Dict[str, Any],
        attack_stages: List[Dict[str, str]]
    ) -> str:
        """
        Generate a concise investigation summary.
        """

        if not logs:
            return "No security events were provided for investigation."

        event_count = len(logs)

        event_types = evidence.get(
            "event_types",
            []
        )

        ioc_count = (
            len(evidence.get("ip_addresses", []))
            + len(evidence.get("domains", []))
            + len(evidence.get("urls", []))
            + len(
                evidence.get(
                    "hashes",
                    {}
                ).get("md5", [])
            )
            + len(
                evidence.get(
                    "hashes",
                    {}
                ).get("sha1", [])
            )
            + len(
                evidence.get(
                    "hashes",
                    {}
                ).get("sha256", [])
            )
        )

        risk_level = cls.determine_investigation_level(
            detection_result,
            hunting_result
        )

        summary_parts = [
            f"{event_count} security event(s) were investigated.",
            f"Overall investigation level: {risk_level}.",
            f"{ioc_count} unique IOC(s) were identified."
        ]

        if event_types:
            summary_parts.append(
                "Observed event types: "
                + ", ".join(event_types)
                + "."
            )

        if attack_stages:
            stages = sorted(
                {
                    stage["attack_stage"]
                    for stage in attack_stages
                }
            )

            summary_parts.append(
                "Possible attack stages: "
                + ", ".join(stages)
                + "."
            )

        findings_count = hunting_result.get(
            "findings_count",
            0
        )

        if findings_count:
            summary_parts.append(
                f"{findings_count} threat-hunting "
                "finding(s) require review."
            )

        return " ".join(summary_parts)

    # ---------------------------------------------------------
    # COMPLETE INVESTIGATION
    # ---------------------------------------------------------

    @classmethod
    def investigate(
        cls,
        logs: List[Dict[str, Any]],
        detection_result: Dict[str, Any] | None = None,
        hunting_result: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """
        Perform a complete investigation.

        Parameters:
            logs:
                Processed security logs.

            detection_result:
                Optional result from DetectionAgent.

            hunting_result:
                Optional result from HunterAgent.
        """

        if not logs:
            return {
                "status": "no_data",
                "events_investigated": 0,
                "investigation_level": "informational",
                "summary": (
                    "No security events were provided "
                    "for investigation."
                ),
                "evidence": {},
                "timeline": [],
                "correlations": [],
                "attack_stages": [],
                "mitre_techniques": [],
                "affected_assets": {}
            }

        detection_result = (
            detection_result
            or {}
        )

        hunting_result = (
            hunting_result
            or {}
        )

        # -----------------------------------------------------
        # Investigation components
        # -----------------------------------------------------

        evidence = cls.collect_evidence(
            logs
        )

        timeline = cls.build_timeline(
            logs
        )

        correlations = cls.correlate_events(
            logs
        )

        attack_stages = cls.identify_attack_stages(
            logs
        )

        mitre_techniques = cls.analyze_mitre(
            logs
        )

        affected_assets = cls.identify_affected_assets(
            logs
        )

        detection_analysis = cls.analyze_detection(
            detection_result
        )

        hunting_analysis = cls.analyze_hunting(
            hunting_result
        )

        investigation_level = (
            cls.determine_investigation_level(
                detection_analysis,
                hunting_analysis
            )
        )

        summary = cls.generate_summary(
            logs,
            detection_analysis,
            hunting_analysis,
            evidence,
            attack_stages
        )

        # -----------------------------------------------------
        # Final investigation result
        # -----------------------------------------------------

        return {
            "status": "investigated",
            "events_investigated": len(logs),

            "investigation_level": (
                investigation_level
            ),

            "summary": summary,

            "detection": detection_analysis,

            "threat_hunting": hunting_analysis,

            "evidence": evidence,

            "timeline": timeline,

            "correlations": correlations,

            "attack_stages": attack_stages,

            "mitre_techniques": mitre_techniques,

            "affected_assets": affected_assets
        }


# -------------------------------------------------------------
# HELPER FUNCTION
# -------------------------------------------------------------

def investigate_events(
    logs: List[Dict[str, Any]],
    detection_result: Dict[str, Any] | None = None,
    hunting_result: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    """
    Convenience function for running an investigation.
    """

    return InvestigatorAgent.investigate(
        logs,
        detection_result,
        hunting_result
    )