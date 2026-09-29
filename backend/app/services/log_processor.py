import re
import json
from datetime import datetime
from typing import Any, Dict, List, Optional


class LogProcessor:
    """
    SOC Log Processing Engine

    Responsibilities:
    - Normalize raw security logs
    - Detect log source
    - Extract IOCs
    - Identify event types
    - Estimate severity
    - Map common events to MITRE ATT&CK techniques
    - Prepare structured data for AI analysis
    """

    # ==========================================================
    # Regular Expressions
    # ==========================================================

    IPV4_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    )

    URL_PATTERN = re.compile(
        r"https?://[^\s\"'<>]+",
        re.IGNORECASE
    )

    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|net|org|edu|gov|io|co|in|biz|info|xyz|dev|ai|me)\b",
        re.IGNORECASE
    )

    MD5_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    )

    SHA1_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    )

    SHA256_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    )

    # ==========================================================
    # General Utilities
    # ==========================================================

    @staticmethod
    def clean_log(log_text: str) -> str:
        """
        Remove unnecessary whitespace and normalize a log.
        """

        if not log_text:
            return ""

        return " ".join(log_text.strip().split())

    @staticmethod
    def extract_timestamp(log_text: str) -> Optional[str]:
        """
        Attempt to extract common timestamp formats.
        """

        patterns = [
            # 2026-09-26 21:30:45
            r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}",

            # 2026-09-26T21:30:45
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",

            # Sep 26 21:30:45
            r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
            r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
        ]

        for pattern in patterns:

            match = re.search(
                pattern,
                log_text,
                re.IGNORECASE
            )

            if match:
                return match.group(0)

        return None

    # ==========================================================
    # IP Address Extraction
    # ==========================================================

    @staticmethod
    def extract_ip_addresses(log_text: str) -> List[str]:
        """
        Extract IPv4 addresses.
        """

        if not log_text:
            return []

        ips = LogProcessor.IPV4_PATTERN.findall(log_text)

        return sorted(set(ips))

    # ==========================================================
    # URL Extraction
    # ==========================================================

    @staticmethod
    def extract_urls(log_text: str) -> List[str]:
        """
        Extract HTTP and HTTPS URLs.
        """

        if not log_text:
            return []

        urls = LogProcessor.URL_PATTERN.findall(log_text)

        return sorted(set(urls))

    # ==========================================================
    # Domain Extraction
    # ==========================================================

    @staticmethod
    def extract_domains(log_text: str) -> List[str]:
        """
        Extract domain names.
        """

        if not log_text:
            return []

        domains = LogProcessor.DOMAIN_PATTERN.findall(log_text)

        return sorted(set(
            domain.lower()
            for domain in domains
        ))

    # ==========================================================
    # Hash Extraction
    # ==========================================================

    @staticmethod
    def extract_hashes(log_text: str) -> Dict[str, List[str]]:
        """
        Extract MD5, SHA1 and SHA256 hashes.
        """

        if not log_text:
            return {
                "md5": [],
                "sha1": [],
                "sha256": []
            }

        sha256 = sorted(
            set(LogProcessor.SHA256_PATTERN.findall(log_text))
        )

        sha1 = sorted(
            set(LogProcessor.SHA1_PATTERN.findall(log_text))
        )

        md5 = sorted(
            set(LogProcessor.MD5_PATTERN.findall(log_text))
        )

        return {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256
        }

    # ==========================================================
    # IOC Extraction
    # ==========================================================

    @staticmethod
    def extract_iocs(log_text: str) -> Dict[str, Any]:
        """
        Extract Indicators of Compromise.
        """

        return {
            "ip_addresses":
                LogProcessor.extract_ip_addresses(log_text),

            "domains":
                LogProcessor.extract_domains(log_text),

            "urls":
                LogProcessor.extract_urls(log_text),

            "hashes":
                LogProcessor.extract_hashes(log_text)
        }

    # ==========================================================
    # Log Source Detection
    # ==========================================================

    @staticmethod
    def detect_log_source(log_text: str) -> str:
        """
        Detect the likely source of a log.
        """

        text = log_text.lower()

        # Windows
        windows_keywords = [
            "eventid=",
            "event id",
            "windows event",
            "winlog",
            "security-auditing"
        ]

        if any(keyword in text for keyword in windows_keywords):
            return "windows_event_log"

        # Linux / Syslog
        linux_keywords = [
            "sshd",
            "systemd",
            "syslog",
            "auth.log",
            "kern.log",
            "ubuntu",
            "linux"
        ]

        if any(keyword in text for keyword in linux_keywords):
            return "linux_syslog"

        # Apache
        if "apache" in text or "httpd" in text:
            return "apache"

        # Nginx
        if "nginx" in text:
            return "nginx"

        # Suricata
        if "suricata" in text or "eve.json" in text:
            return "suricata"

        # Snort
        if "snort" in text:
            return "snort"

        # Firewall
        firewall_keywords = [
            "firewall",
            "iptables",
            "deny",
            "blocked connection",
            "allow connection",
            "fortigate",
            "palo alto",
            "checkpoint"
        ]

        if any(keyword in text for keyword in firewall_keywords):
            return "firewall"

        # SIEM
        siem_keywords = [
            "splunk",
            "qradar",
            "elastic",
            "elasticsearch",
            "siem"
        ]

        if any(keyword in text for keyword in siem_keywords):
            return "siem"

        return "unknown"

    # ==========================================================
    # Event Type Detection
    # ==========================================================

    @staticmethod
    def detect_event_type(log_text: str) -> str:
        """
        Detect security event type.
        """

        text = log_text.lower()

        # Authentication
        if any(
            keyword in text
            for keyword in [
                "failed login",
                "login failed",
                "authentication failure",
                "invalid password",
                "authentication failed"
            ]
        ):
            return "authentication_failure"

        if any(
            keyword in text
            for keyword in [
                "successful login",
                "login successful",
                "authentication success"
            ]
        ):
            return "authentication_success"

        # Brute force
        if any(
            keyword in text
            for keyword in [
                "brute force",
                "multiple failed login",
                "repeated login attempts"
            ]
        ):
            return "brute_force"

        # Malware
        if any(
            keyword in text
            for keyword in [
                "malware",
                "trojan",
                "ransomware",
                "backdoor",
                "virus"
            ]
        ):
            return "malware"

        # Network scanning
        if any(
            keyword in text
            for keyword in [
                "port scan",
                "network scan",
                "nmap",
                "scanning detected"
            ]
        ):
            return "network_scanning"

        # SQL Injection
        if any(
            keyword in text
            for keyword in [
                "sql injection",
                "union select",
                "' or 1=1",
                "select * from"
            ]
        ):
            return "sql_injection"

        # XSS
        if any(
            keyword in text
            for keyword in [
                "cross-site scripting",
                "<script>",
                "xss attack"
            ]
        ):
            return "xss"

        # DoS
        if any(
            keyword in text
            for keyword in [
                "denial of service",
                "dos attack",
                "ddos attack",
                "flood detected"
            ]
        ):
            return "dos_attack"

        # Suspicious PowerShell
        if "powershell" in text:
            return "powershell_activity"

        # Malware download
        if any(
            keyword in text
            for keyword in [
                "malicious download",
                "suspicious file download",
                "payload downloaded"
            ]
        ):
            return "malicious_download"

        return "unknown"

    # ==========================================================
    # Severity Detection
    # ==========================================================

    @staticmethod
    def determine_severity(
        event_type: str,
        log_text: str
    ) -> str:
        """
        Estimate severity using simple rules.

        Final severity should later be determined by
        the AI analysis engine and security rules.
        """

        text = log_text.lower()

        critical_events = [
            "ransomware",
            "backdoor",
            "data exfiltration",
            "privilege escalation"
        ]

        high_events = [
            "malware",
            "trojan",
            "brute_force",
            "sql_injection",
            "xss",
            "dos_attack"
        ]

        if any(
            keyword in text
            for keyword in critical_events
        ):
            return "critical"

        if event_type in high_events:
            return "high"

        if event_type in [
            "network_scanning",
            "powershell_activity"
        ]:
            return "medium"

        if event_type in [
            "authentication_failure",
            "authentication_success"
        ]:
            return "low"

        return "unknown"

    # ==========================================================
    # MITRE ATT&CK Mapping
    # ==========================================================

    @staticmethod
    def map_mitre_attack(event_type: str) -> List[Dict[str, str]]:
        """
        Map common event types to MITRE ATT&CK techniques.
        """

        mapping = {

            "brute_force": [
                {
                    "technique_id": "T1110",
                    "technique": "Brute Force"
                }
            ],

            "powershell_activity": [
                {
                    "technique_id": "T1059.001",
                    "technique": "PowerShell"
                }
            ],

            "network_scanning": [
                {
                    "technique_id": "T1046",
                    "technique": "Network Service Scanning"
                }
            ],

            "sql_injection": [
                {
                    "technique_id": "T1190",
                    "technique": "Exploit Public-Facing Application"
                }
            ],

            "malware": [
                {
                    "technique_id": "T1204",
                    "technique": "User Execution"
                }
            ],

            "malicious_download": [
                {
                    "technique_id": "T1105",
                    "technique": "Ingress Tool Transfer"
                }
            ]
        }

        return mapping.get(event_type, [])

    # ==========================================================
    # Log Summary
    # ==========================================================

    @staticmethod
    def generate_log_summary(log_text: str) -> str:
        """
        Generate a basic machine-readable summary.
        """

        cleaned_log = LogProcessor.clean_log(log_text)

        if len(cleaned_log) > 250:
            return cleaned_log[:250] + "..."

        return cleaned_log

    # ==========================================================
    # Normalize Log
    # ==========================================================

    @staticmethod
    def normalize_log(log_text: str) -> Dict[str, Any]:
        """
        Convert raw log into a standardized SOC structure.
        """

        if not log_text:
            raise ValueError("Log text cannot be empty.")

        cleaned_log = LogProcessor.clean_log(log_text)

        event_type = LogProcessor.detect_event_type(
            cleaned_log
        )

        return {
            "raw_log": log_text,
            "cleaned_log": cleaned_log,

            "timestamp": (
                LogProcessor.extract_timestamp(cleaned_log)
                or datetime.utcnow().isoformat()
            ),

            "log_source":
                LogProcessor.detect_log_source(cleaned_log),

            "event_type":
                event_type,

            "severity":
                LogProcessor.determine_severity(
                    event_type,
                    cleaned_log
                ),

            "iocs":
                LogProcessor.extract_iocs(cleaned_log),

            "mitre_attack":
                LogProcessor.map_mitre_attack(event_type),

            "summary":
                LogProcessor.generate_log_summary(cleaned_log)
        }

    # ==========================================================
    # Process Single Log
    # ==========================================================

    @staticmethod
    def process_log(log_text: str) -> Dict[str, Any]:
        """
        Complete processing pipeline for one log.
        """

        return LogProcessor.normalize_log(log_text)

    # ==========================================================
    # Process Multiple Logs
    # ==========================================================

    @staticmethod
    def process_logs(
        logs: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Process multiple security logs.
        """

        results = []

        for log in logs:

            if not log or not log.strip():
                continue

            try:
                result = LogProcessor.process_log(log)
                results.append(result)

            except ValueError:
                continue

        return results

    # ==========================================================
    # JSON Log Processing
    # ==========================================================

    @staticmethod
    def process_json_log(
        log_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process a JSON-formatted security log.
        """

        if not isinstance(log_data, dict):
            raise ValueError(
                "JSON log must be provided as a dictionary."
            )

        # Convert JSON into searchable text
        json_text = json.dumps(
            log_data,
            ensure_ascii=False
        )

        result = LogProcessor.process_log(json_text)

        # Preserve original structured data
        result["structured_log"] = log_data

        return result