"""
Threat Hunter Agent
-------------------

Responsible for proactive threat hunting across security events.

The Hunter Agent:
- Searches for suspicious patterns
- Correlates related events
- Detects repeated suspicious activity
- Identifies possible attack chains
- Looks for unusual authentication behavior
- Detects reconnaissance activity
- Detects possible lateral movement
- Detects suspicious PowerShell activity
- Generates hunting findings

This module works with processed logs and does not directly
execute commands on systems.
"""

from collections import Counter, defaultdict
from typing import Any, Dict, List


class HunterAgent:
    """
    Proactive threat-hunting engine for the SOC Analyst.
    """

    # ---------------------------------------------------------
    # EVENT GROUPS
    # ---------------------------------------------------------

    AUTH_EVENTS = {
        "authentication_failure",
        "authentication_success",
        "brute_force"
    }

    RECON_EVENTS = {
        "network_scanning"
    }

    EXECUTION_EVENTS = {
        "powershell_activity",
        "command_execution"
    }

    MALWARE_EVENTS = {
        "malware",
        "ransomware",
        "malicious_download"
    }

    # ---------------------------------------------------------
    # HUNTING THRESHOLDS
    # ---------------------------------------------------------

    FAILED_LOGIN_THRESHOLD = 5
    SCANNING_THRESHOLD = 3
    POWERSHELL_THRESHOLD = 2

    # ---------------------------------------------------------
    # BASIC EVENT STATISTICS
    # ---------------------------------------------------------

    @staticmethod
    def count_event_types(
        logs: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """
        Count how many times each event type appears.
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
    # IP STATISTICS
    # ---------------------------------------------------------

    @staticmethod
    def count_source_ips(
        logs: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """
        Count occurrences of source IP addresses.
        """

        ip_counter = Counter()

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
                ip_counter[ip] += 1

        return dict(ip_counter)

    # ---------------------------------------------------------
    # FAILED LOGIN HUNT
    # ---------------------------------------------------------

    @classmethod
    def hunt_brute_force(
        cls,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect repeated authentication failures
        from the same source IP.
        """

        failed_attempts = Counter()

        for log in logs:

            event_type = log.get(
                "event_type",
                ""
            )

            if event_type not in cls.AUTH_EVENTS:
                continue

            if event_type != "authentication_failure":
                continue

            iocs = log.get(
                "iocs",
                {}
            )

            for ip in iocs.get(
                "ip_addresses",
                []
            ):
                failed_attempts[ip] += 1

        findings = []

        for ip, count in failed_attempts.items():

            if count >= cls.FAILED_LOGIN_THRESHOLD:

                findings.append({
                    "hunt_type": "brute_force",
                    "source_ip": ip,
                    "failed_attempts": count,
                    "severity": "high",
                    "confidence": 0.90,
                    "description": (
                        f"{count} authentication failures "
                        f"were observed from {ip}."
                    )
                })

        return findings

    # ---------------------------------------------------------
    # NETWORK SCANNING HUNT
    # ---------------------------------------------------------

    @classmethod
    def hunt_network_scanning(
        cls,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect repeated network scanning activity.
        """

        scan_counter = Counter()

        for log in logs:

            if log.get("event_type") != "network_scanning":
                continue

            iocs = log.get(
                "iocs",
                {}
            )

            for ip in iocs.get(
                "ip_addresses",
                []
            ):
                scan_counter[ip] += 1

        findings = []

        for ip, count in scan_counter.items():

            if count >= cls.SCANNING_THRESHOLD:

                findings.append({
                    "hunt_type": "network_reconnaissance",
                    "source_ip": ip,
                    "scan_events": count,
                    "severity": "medium",
                    "confidence": 0.85,
                    "description": (
                        f"Repeated network scanning activity "
                        f"was observed from {ip}."
                    )
                })

        return findings

    # ---------------------------------------------------------
    # POWERSHELL HUNT
    # ---------------------------------------------------------

    @classmethod
    def hunt_powershell(
        cls,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect repeated PowerShell execution.
        """

        powershell_counter = Counter()

        for log in logs:

            if log.get("event_type") != "powershell_activity":
                continue

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
                    powershell_counter[ip] += 1

            else:
                powershell_counter["unknown_source"] += 1

        findings = []

        for source, count in powershell_counter.items():

            if count >= cls.POWERSHELL_THRESHOLD:

                findings.append({
                    "hunt_type": "powershell_activity",
                    "source": source,
                    "event_count": count,
                    "severity": "medium",
                    "confidence": 0.75,
                    "description": (
                        f"Repeated PowerShell activity "
                        f"was observed from {source}."
                    )
                })

        return findings

    # ---------------------------------------------------------
    # MALWARE HUNT
    # ---------------------------------------------------------

    @classmethod
    def hunt_malware(
        cls,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Search for malware-related events.
        """

        findings = []

        for log in logs:

            event_type = log.get(
                "event_type",
                ""
            )

            if event_type not in cls.MALWARE_EVENTS:
                continue

            findings.append({
                "hunt_type": "malware_activity",
                "event_type": event_type,
                "severity": "critical",
                "confidence": 0.90,
                "description": (
                    f"Potential {event_type.replace('_', ' ')} "
                    "activity was identified."
                ),
                "log": log
            })

        return findings

    # ---------------------------------------------------------
    # SUSPICIOUS IOC HUNT
    # ---------------------------------------------------------

    @classmethod
    def hunt_suspicious_iocs(
        cls,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Search for IOCs that appear repeatedly.
        """

        ip_counter = Counter()
        domain_counter = Counter()
        hash_counter = Counter()

        for log in logs:

            iocs = log.get(
                "iocs",
                {}
            )

            for ip in iocs.get(
                "ip_addresses",
                []
            ):
                ip_counter[ip] += 1

            for domain in iocs.get(
                "domains",
                []
            ):
                domain_counter[domain] += 1

            hashes = iocs.get(
                "hashes",
                {}
            )

            for hash_value in hashes.get(
                "md5",
                []
            ):
                hash_counter[hash_value] += 1

            for hash_value in hashes.get(
                "sha1",
                []
            ):
                hash_counter[hash_value] += 1

            for hash_value in hashes.get(
                "sha256",
                []
            ):
                hash_counter[hash_value] += 1

        findings = []

        for ip, count in ip_counter.items():

            if count >= 3:

                findings.append({
                    "hunt_type": "repeated_ip",
                    "ioc": ip,
                    "occurrences": count,
                    "severity": "medium",
                    "confidence": 0.70,
                    "description": (
                        f"IP address {ip} appeared "
                        f"{count} times across security events."
                    )
                })

        for domain, count in domain_counter.items():

            if count >= 3:

                findings.append({
                    "hunt_type": "repeated_domain",
                    "ioc": domain,
                    "occurrences": count,
                    "severity": "medium",
                    "confidence": 0.70,
                    "description": (
                        f"Domain {domain} appeared "
                        f"{count} times across security events."
                    )
                })

        for file_hash, count in hash_counter.items():

            if count >= 2:

                findings.append({
                    "hunt_type": "repeated_file_hash",
                    "ioc": file_hash,
                    "occurrences": count,
                    "severity": "high",
                    "confidence": 0.80,
                    "description": (
                        "The same file hash appeared in "
                        f"{count} security events."
                    )
                })

        return findings

    # ---------------------------------------------------------
    # ATTACK CHAIN HUNT
    # ---------------------------------------------------------

    @classmethod
    def hunt_attack_chain(
        cls,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Identify a possible multi-stage attack pattern.

        Example:

        Authentication failure
                ↓
        Authentication success
                ↓
        PowerShell execution
                ↓
        Malicious download
        """

        event_types = [
            log.get(
                "event_type",
                "unknown"
            )
            for log in logs
        ]

        findings = []

        required_stages = [
            "authentication_failure",
            "authentication_success",
            "powershell_activity",
            "malicious_download"
        ]

        present_stages = [
            stage
            for stage in required_stages
            if stage in event_types
        ]

        if len(present_stages) >= 3:

            findings.append({
                "hunt_type": "possible_attack_chain",
                "stages_detected": present_stages,
                "stage_count": len(present_stages),
                "severity": "critical",
                "confidence": 0.85,
                "description": (
                    "Multiple security events form a possible "
                    "multi-stage attack sequence."
                )
            })

        return findings

    # ---------------------------------------------------------
    # ANOMALY HUNT
    # ---------------------------------------------------------

    @classmethod
    def hunt_anomalies(
        cls,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect unusually frequent event types.
        """

        if not logs:
            return []

        event_counts = cls.count_event_types(
            logs
        )

        findings = []

        for event_type, count in event_counts.items():

            if count >= 10:

                findings.append({
                    "hunt_type": "event_frequency_anomaly",
                    "event_type": event_type,
                    "occurrences": count,
                    "severity": "medium",
                    "confidence": 0.65,
                    "description": (
                        f"Event type '{event_type}' occurred "
                        f"{count} times and may require investigation."
                    )
                })

        return findings

    # ---------------------------------------------------------
    # COMPLETE HUNT
    # ---------------------------------------------------------

    @classmethod
    def hunt(
        cls,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Run all threat-hunting rules.
        """

        if not logs:

            return {
                "logs_analyzed": 0,
                "findings_count": 0,
                "findings": [],
                "status": "no_data"
            }

        findings: List[Dict[str, Any]] = []

        findings.extend(
            cls.hunt_brute_force(logs)
        )

        findings.extend(
            cls.hunt_network_scanning(logs)
        )

        findings.extend(
            cls.hunt_powershell(logs)
        )

        findings.extend(
            cls.hunt_malware(logs)
        )

        findings.extend(
            cls.hunt_suspicious_iocs(logs)
        )

        findings.extend(
            cls.hunt_attack_chain(logs)
        )

        findings.extend(
            cls.hunt_anomalies(logs)
        )

        # -----------------------------------------------------
        # Severity statistics
        # -----------------------------------------------------

        severity_counts = Counter(
            finding.get(
                "severity",
                "unknown"
            )
            for finding in findings
        )

        # -----------------------------------------------------
        # Overall hunting status
        # -----------------------------------------------------

        if any(
            finding.get("severity") == "critical"
            for finding in findings
        ):
            overall_status = "critical"

        elif any(
            finding.get("severity") == "high"
            for finding in findings
        ):
            overall_status = "high"

        elif findings:
            overall_status = "suspicious"

        else:
            overall_status = "no_significant_findings"

        return {
            "logs_analyzed": len(logs),
            "findings_count": len(findings),
            "overall_status": overall_status,
            "severity_counts": dict(
                severity_counts
            ),
            "findings": findings
        }


# -------------------------------------------------------------
# HELPER FUNCTION
# -------------------------------------------------------------

def hunt_threats(
    logs: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Convenience function for running threat hunting.
    """

    return HunterAgent.hunt(logs)