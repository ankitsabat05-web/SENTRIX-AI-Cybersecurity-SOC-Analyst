"""
Security Rule Engine
--------------------

Centralized rule-processing engine for the AI Cybersecurity
SOC Analyst.

Responsibilities:

- Store security detection rules.
- Evaluate processed security logs.
- Match event types.
- Match keywords.
- Match severity.
- Match IOC presence.
- Match source/log types.
- Calculate rule confidence.
- Generate security findings.

This is a deterministic rule engine. A matched rule is an
indicator for investigation, not proof of compromise.
"""

from typing import Any, Dict, List, Optional


class RuleEngine:
    """
    Centralized security rule evaluation engine.
    """

    # ---------------------------------------------------------
    # DEFAULT RULES
    # ---------------------------------------------------------

    DEFAULT_RULES: List[Dict[str, Any]] = [

        {
            "rule_id": "RULE-001",
            "name": "Possible Brute Force Attack",
            "description": (
                "Detect repeated authentication failures "
                "that may indicate brute-force activity."
            ),
            "enabled": True,
            "severity": "high",
            "event_types": [
                "brute_force"
            ],
            "keywords": [
                "brute force",
                "multiple failed login",
                "repeated login attempts"
            ],
            "mitre_techniques": [
                "T1110"
            ]
        },

        {
            "rule_id": "RULE-002",
            "name": "Malware Activity",
            "description": (
                "Detect indicators associated with potentially "
                "malicious software."
            ),
            "enabled": True,
            "severity": "critical",
            "event_types": [
                "malware"
            ],
            "keywords": [
                "malware",
                "trojan",
                "virus",
                "backdoor"
            ],
            "mitre_techniques": [
                "T1204"
            ]
        },

        {
            "rule_id": "RULE-003",
            "name": "Ransomware Indicator",
            "description": (
                "Detect keywords associated with ransomware activity."
            ),
            "enabled": True,
            "severity": "critical",
            "event_types": [
                "ransomware"
            ],
            "keywords": [
                "ransomware",
                "encrypted files",
                "ransom note",
                "file encryption"
            ],
            "mitre_techniques": [],
        },

        {
            "rule_id": "RULE-004",
            "name": "Network Scanning",
            "description": (
                "Detect possible network reconnaissance activity."
            ),
            "enabled": True,
            "severity": "medium",
            "event_types": [
                "network_scanning"
            ],
            "keywords": [
                "port scan",
                "network scan",
                "nmap",
                "scanning detected"
            ],
            "mitre_techniques": [
                "T1046"
            ]
        },

        {
            "rule_id": "RULE-005",
            "name": "PowerShell Activity",
            "description": (
                "Detect PowerShell execution that may require "
                "additional investigation."
            ),
            "enabled": True,
            "severity": "medium",
            "event_types": [
                "powershell_activity"
            ],
            "keywords": [
                "powershell",
                "powershell.exe",
                "invoke-expression",
                "encodedcommand"
            ],
            "mitre_techniques": [
                "T1059.001"
            ]
        },

        {
            "rule_id": "RULE-006",
            "name": "SQL Injection",
            "description": (
                "Detect possible SQL injection attempts."
            ),
            "enabled": True,
            "severity": "high",
            "event_types": [
                "sql_injection"
            ],
            "keywords": [
                "sql injection",
                "union select",
                "' or 1=1",
                "select * from"
            ],
            "mitre_techniques": [
                "T1190"
            ]
        },

        {
            "rule_id": "RULE-007",
            "name": "Cross-Site Scripting",
            "description": (
                "Detect possible XSS activity."
            ),
            "enabled": True,
            "severity": "high",
            "event_types": [
                "xss"
            ],
            "keywords": [
                "cross-site scripting",
                "xss attack",
                "<script>"
            ],
            "mitre_techniques": []
        },

        {
            "rule_id": "RULE-008",
            "name": "Suspicious File Download",
            "description": (
                "Detect potentially suspicious file download activity."
            ),
            "enabled": True,
            "severity": "high",
            "event_types": [
                "malicious_download"
            ],
            "keywords": [
                "malicious download",
                "suspicious file download",
                "payload downloaded"
            ],
            "mitre_techniques": [
                "T1105"
            ]
        },

        {
            "rule_id": "RULE-009",
            "name": "Authentication Failure",
            "description": (
                "Detect failed authentication activity."
            ),
            "enabled": True,
            "severity": "low",
            "event_types": [
                "authentication_failure"
            ],
            "keywords": [
                "failed login",
                "login failed",
                "authentication failure",
                "invalid password"
            ],
            "mitre_techniques": [
                "T1110"
            ]
        },

        {
            "rule_id": "RULE-010",
            "name": "Suspicious External IOC",
            "description": (
                "Detect logs containing external indicators "
                "of compromise."
            ),
            "enabled": True,
            "severity": "medium",
            "event_types": [],
            "keywords": [],
            "requires_ioc": True,
            "mitre_techniques": []
        }
    ]

    # ---------------------------------------------------------
    # INITIALIZATION
    # ---------------------------------------------------------

    def __init__(
        self,
        rules: Optional[
            List[Dict[str, Any]]
        ] = None
    ) -> None:

        self.rules = (
            rules
            if rules is not None
            else [
                rule.copy()
                for rule in self.DEFAULT_RULES
            ]
        )

    # ---------------------------------------------------------
    # RULE VALIDATION
    # ---------------------------------------------------------

    @staticmethod
    def validate_rule(
        rule: Dict[str, Any]
    ) -> bool:
        """
        Validate the minimum structure of a security rule.
        """

        required_fields = [
            "rule_id",
            "name",
            "enabled",
            "severity"
        ]

        for field in required_fields:

            if field not in rule:
                return False

        if not isinstance(
            rule["rule_id"],
            str
        ):
            return False

        if not isinstance(
            rule["name"],
            str
        ):
            return False

        if not isinstance(
            rule["enabled"],
            bool
        ):
            return False

        valid_severities = {
            "critical",
            "high",
            "medium",
            "low",
            "informational"
        }

        if rule["severity"] not in valid_severities:
            return False

        return True

    # ---------------------------------------------------------
    # ADD RULE
    # ---------------------------------------------------------

    def add_rule(
        self,
        rule: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Add a new security rule.
        """

        if not self.validate_rule(
            rule
        ):
            raise ValueError(
                "Invalid security rule."
            )

        if self.get_rule(
            rule["rule_id"]
        ):
            raise ValueError(
                "Rule ID already exists."
            )

        self.rules.append(
            rule
        )

        return rule

    # ---------------------------------------------------------
    # GET RULE
    # ---------------------------------------------------------

    def get_rule(
        self,
        rule_id: str
    ) -> Optional[
        Dict[str, Any]
    ]:
        """
        Find a rule by ID.
        """

        for rule in self.rules:

            if rule.get(
                "rule_id"
            ) == rule_id:

                return rule

        return None

    # ---------------------------------------------------------
    # ENABLE RULE
    # ---------------------------------------------------------

    def enable_rule(
        self,
        rule_id: str
    ) -> bool:
        """
        Enable a security rule.
        """

        rule = self.get_rule(
            rule_id
        )

        if rule is None:
            return False

        rule["enabled"] = True

        return True

    # ---------------------------------------------------------
    # DISABLE RULE
    # ---------------------------------------------------------

    def disable_rule(
        self,
        rule_id: str
    ) -> bool:
        """
        Disable a security rule.
        """

        rule = self.get_rule(
            rule_id
        )

        if rule is None:
            return False

        rule["enabled"] = False

        return True

    # ---------------------------------------------------------
    # DELETE RULE
    # ---------------------------------------------------------

    def delete_rule(
        self,
        rule_id: str
    ) -> bool:
        """
        Delete a security rule.
        """

        for index, rule in enumerate(
            self.rules
        ):

            if rule.get(
                "rule_id"
            ) == rule_id:

                self.rules.pop(
                    index
                )

                return True

        return False

    # ---------------------------------------------------------
    # GET ACTIVE RULES
    # ---------------------------------------------------------

    def get_active_rules(
        self
    ) -> List[
        Dict[str, Any]
    ]:
        """
        Return only enabled rules.
        """

        return [
            rule
            for rule in self.rules
            if rule.get(
                "enabled",
                False
            )
        ]

    # ---------------------------------------------------------
    # MATCH EVENT TYPE
    # ---------------------------------------------------------

    @staticmethod
    def match_event_type(
        log: Dict[str, Any],
        rule: Dict[str, Any]
    ) -> bool:
        """
        Check whether the event type matches the rule.
        """

        event_types = rule.get(
            "event_types",
            []
        )

        if not event_types:
            return True

        event_type = log.get(
            "event_type",
            "unknown"
        )

        return event_type in event_types

    # ---------------------------------------------------------
    # MATCH KEYWORDS
    # ---------------------------------------------------------

    @staticmethod
    def match_keywords(
        log: Dict[str, Any],
        rule: Dict[str, Any]
    ) -> List[str]:
        """
        Find rule keywords present in the log.
        """

        keywords = rule.get(
            "keywords",
            []
        )

        if not keywords:
            return []

        searchable_text = " ".join([
            str(
                log.get(
                    "raw_log",
                    ""
                )
            ),

            str(
                log.get(
                    "cleaned_log",
                    ""
                )
            ),

            str(
                log.get(
                    "description",
                    ""
                )
            ),

            str(
                log.get(
                    "event_type",
                    ""
                )
            )
        ]).lower()

        matched_keywords = []

        for keyword in keywords:

            if keyword.lower() in searchable_text:

                matched_keywords.append(
                    keyword
                )

        return matched_keywords

    # ---------------------------------------------------------
    # MATCH IOC REQUIREMENT
    # ---------------------------------------------------------

    @staticmethod
    def match_ioc_requirement(
        log: Dict[str, Any],
        rule: Dict[str, Any]
    ) -> bool:
        """
        Check whether the rule requires an IOC.
        """

        if not rule.get(
            "requires_ioc",
            False
        ):
            return True

        iocs = log.get(
            "iocs",
            {}
        )

        ip_count = len(
            iocs.get(
                "ip_addresses",
                []
            )
        )

        domain_count = len(
            iocs.get(
                "domains",
                []
            )
        )

        url_count = len(
            iocs.get(
                "urls",
                []
            )
        )

        hashes = iocs.get(
            "hashes",
            {}
        )

        hash_count = (
            len(
                hashes.get(
                    "md5",
                    []
                )
            )
            + len(
                hashes.get(
                    "sha1",
                    []
                )
            )
            + len(
                hashes.get(
                    "sha256",
                    []
                )
            )
        )

        return (
            ip_count
            + domain_count
            + url_count
            + hash_count
        ) > 0

    # ---------------------------------------------------------
    # MATCH RULE
    # ---------------------------------------------------------

    def evaluate_rule(
        self,
        log: Dict[str, Any],
        rule: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluate one rule against one log.
        """

        if not rule.get(
            "enabled",
            False
        ):
            return {
                "matched": False,
                "rule_id": rule.get(
                    "rule_id"
                ),
                "reason": "Rule disabled"
            }

        event_match = self.match_event_type(
            log,
            rule
        )

        matched_keywords = (
            self.match_keywords(
                log,
                rule
            )
        )

        keyword_match = (
            not rule.get(
                "keywords",
                []
            )
            or bool(
                matched_keywords
            )
        )

        ioc_match = (
            self.match_ioc_requirement(
                log,
                rule
            )
        )

        matched = (
            event_match
            and keyword_match
            and ioc_match
        )

        confidence = 0

        if event_match:
            confidence += 50

        if matched_keywords:
            confidence += min(
                len(
                    matched_keywords
                ) * 15,
                30
            )

        if rule.get(
            "requires_ioc",
            False
        ) and ioc_match:
            confidence += 20

        confidence = min(
            confidence,
            100
        )

        return {
            "matched": matched,

            "rule_id": rule.get(
                "rule_id"
            ),

            "rule_name": rule.get(
                "name"
            ),

            "severity": rule.get(
                "severity",
                "unknown"
            ),

            "confidence": confidence,

            "matched_keywords": (
                matched_keywords
            ),

            "event_type": log.get(
                "event_type",
                "unknown"
            ),

            "mitre_techniques": rule.get(
                "mitre_techniques",
                []
            ),

            "description": rule.get(
                "description",
                ""
            )
        }

    # ---------------------------------------------------------
    # EVALUATE LOG
    # ---------------------------------------------------------

    def evaluate_log(
        self,
        log: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluate all active rules against a single log.
        """

        if not log:

            return {
                "status": "no_data",
                "rules_evaluated": 0,
                "matched_rules": []
            }

        matched_rules = []

        active_rules = (
            self.get_active_rules()
        )

        for rule in active_rules:

            result = self.evaluate_rule(
                log,
                rule
            )

            if result.get(
                "matched",
                False
            ):
                matched_rules.append(
                    result
                )

        return {
            "status": "evaluated",

            "rules_evaluated": len(
                active_rules
            ),

            "rules_matched": len(
                matched_rules
            ),

            "matched_rules": matched_rules
        }

    # ---------------------------------------------------------
    # EVALUATE MULTIPLE LOGS
    # ---------------------------------------------------------

    def evaluate_logs(
        self,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Evaluate all rules against multiple logs.
        """

        if not logs:

            return {
                "status": "no_data",
                "logs_evaluated": 0,
                "findings": []
            }

        findings = []

        for index, log in enumerate(
            logs
        ):

            result = self.evaluate_log(
                log
            )

            for matched_rule in result.get(
                "matched_rules",
                []
            ):

                findings.append({
                    **matched_rule,

                    "log_index": index
                })

        return {
            "status": "evaluated",

            "logs_evaluated": len(
                logs
            ),

            "rules_available": len(
                self.get_active_rules()
            ),

            "findings_count": len(
                findings
            ),

            "findings": findings
        }

    # ---------------------------------------------------------
    # SEVERITY SUMMARY
    # ---------------------------------------------------------

    @staticmethod
    def generate_severity_summary(
        findings: List[
            Dict[str, Any]
        ]
    ) -> Dict[str, int]:
        """
        Count findings by severity.
        """

        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }

        for finding in findings:

            severity = finding.get(
                "severity",
                "informational"
            )

            if severity in summary:
                summary[severity] += 1

        return summary

    # ---------------------------------------------------------
    # GENERATE RULE REPORT
    # ---------------------------------------------------------

    def generate_report(
        self,
        logs: List[
            Dict[str, Any]
        ]
    ) -> Dict[str, Any]:
        """
        Generate a complete rule-engine report.
        """

        result = self.evaluate_logs(
            logs
        )

        findings = result.get(
            "findings",
            []
        )

        severity_summary = (
            self.generate_severity_summary(
                findings
            )
        )

        if severity_summary["critical"] > 0:
            overall_severity = "critical"

        elif severity_summary["high"] > 0:
            overall_severity = "high"

        elif severity_summary["medium"] > 0:
            overall_severity = "medium"

        elif severity_summary["low"] > 0:
            overall_severity = "low"

        else:
            overall_severity = "informational"

        return {
            **result,

            "overall_severity": (
                overall_severity
            ),

            "severity_summary": (
                severity_summary
            )
        }


# -------------------------------------------------------------
# GLOBAL INSTANCE
# -------------------------------------------------------------

rule_engine = RuleEngine()


# -------------------------------------------------------------
# HELPER FUNCTION
# -------------------------------------------------------------

def evaluate_security_rules(
    logs: List[
        Dict[str, Any]
    ]
) -> Dict[str, Any]:
    """
    Convenience function for evaluating security rules.
    """
    

    return rule_engine.generate_report(
        logs
    )