from typing import Any, Dict, List


class MitreService:
    """
    MITRE ATT&CK Mapping Service

    Responsibilities:
    - Map security events to MITRE ATT&CK techniques
    - Return technique IDs
    - Return technique names
    - Identify tactics
    - Provide descriptions
    - Provide mitigation guidance
    """

    # ==========================================================
    # MITRE ATT&CK Knowledge Base
    # ==========================================================

    TECHNIQUES: Dict[str, Dict[str, Any]] = {

        # ------------------------------------------------------
        # T1110 - Brute Force
        # ------------------------------------------------------

        "T1110": {
            "technique_id": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access",
            "description": (
                "Adversaries may use brute-force techniques "
                "to obtain valid account credentials."
            ),
            "mitigations": [
                "Enable multi-factor authentication.",
                "Implement account lockout policies.",
                "Monitor repeated authentication failures.",
                "Use strong password policies."
            ]
        },

        # ------------------------------------------------------
        # T1059.001 - PowerShell
        # ------------------------------------------------------

        "T1059.001": {
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution",
            "description": (
                "Adversaries may abuse PowerShell commands "
                "and scripts to execute malicious actions."
            ),
            "mitigations": [
                "Restrict unnecessary PowerShell usage.",
                "Enable PowerShell logging.",
                "Monitor suspicious PowerShell commands.",
                "Use application control where appropriate."
            ]
        },

        # ------------------------------------------------------
        # T1046 - Network Service Scanning
        # ------------------------------------------------------

        "T1046": {
            "technique_id": "T1046",
            "name": "Network Service Scanning",
            "tactic": "Discovery",
            "description": (
                "Adversaries may scan systems to identify "
                "available network services."
            ),
            "mitigations": [
                "Monitor unusual network scanning activity.",
                "Restrict unnecessary network services.",
                "Use network segmentation.",
                "Deploy IDS/IPS monitoring."
            ]
        },

        # ------------------------------------------------------
        # T1190 - Exploit Public-Facing Application
        # ------------------------------------------------------

        "T1190": {
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": (
                "Adversaries may exploit vulnerabilities in "
                "internet-facing applications."
            ),
            "mitigations": [
                "Keep public-facing applications patched.",
                "Perform vulnerability assessments.",
                "Use web application firewalls.",
                "Monitor suspicious application requests."
            ]
        },

        # ------------------------------------------------------
        # T1105 - Ingress Tool Transfer
        # ------------------------------------------------------

        "T1105": {
            "technique_id": "T1105",
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "description": (
                "Adversaries may transfer tools or files "
                "into a compromised environment."
            ),
            "mitigations": [
                "Monitor suspicious file downloads.",
                "Restrict unnecessary outbound connections.",
                "Inspect downloaded files.",
                "Use endpoint detection and response."
            ]
        },

        # ------------------------------------------------------
        # T1078 - Valid Accounts
        # ------------------------------------------------------

        "T1078": {
            "technique_id": "T1078",
            "name": "Valid Accounts",
            "tactic": "Defense Evasion",
            "description": (
                "Adversaries may use legitimate credentials "
                "to access systems."
            ),
            "mitigations": [
                "Enable MFA.",
                "Monitor unusual account activity.",
                "Use least-privilege access.",
                "Review inactive and privileged accounts."
            ]
        },

        # ------------------------------------------------------
        # T1059 - Command and Scripting Interpreter
        # ------------------------------------------------------

        "T1059": {
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": (
                "Adversaries may use command interpreters "
                "and scripting environments to execute commands."
            ),
            "mitigations": [
                "Monitor command execution.",
                "Restrict unnecessary scripting environments.",
                "Enable process and command-line logging."
            ]
        },

        # ------------------------------------------------------
        # T1566 - Phishing
        # ------------------------------------------------------

        "T1566": {
            "technique_id": "T1566",
            "name": "Phishing",
            "tactic": "Initial Access",
            "description": (
                "Adversaries may use phishing messages "
                "to gain initial access."
            ),
            "mitigations": [
                "Deploy email security controls.",
                "Use phishing-resistant authentication.",
                "Train users to identify suspicious messages.",
                "Scan attachments and URLs."
            ]
        },

        # ------------------------------------------------------
        # T1053 - Scheduled Task/Job
        # ------------------------------------------------------

        "T1053": {
            "technique_id": "T1053",
            "name": "Scheduled Task/Job",
            "tactic": "Persistence",
            "description": (
                "Adversaries may use scheduled tasks or jobs "
                "to maintain persistence."
            ),
            "mitigations": [
                "Monitor creation of scheduled tasks.",
                "Restrict administrative privileges.",
                "Review unusual scheduled jobs."
            ]
        },

        # ------------------------------------------------------
        # T1547 - Boot or Logon Autostart Execution
        # ------------------------------------------------------

        "T1547": {
            "technique_id": "T1547",
            "name": "Boot or Logon Autostart Execution",
            "tactic": "Persistence",
            "description": (
                "Adversaries may configure programs to execute "
                "automatically during system startup or login."
            ),
            "mitigations": [
                "Monitor startup configuration changes.",
                "Restrict administrative privileges.",
                "Review unexpected startup programs."
            ]
        }
    }

    # ==========================================================
    # Event → Technique Mapping
    # ==========================================================

    EVENT_MAPPING: Dict[str, List[str]] = {

        "brute_force": [
            "T1110"
        ],

        "authentication_failure": [
            "T1110"
        ],

        "powershell_activity": [
            "T1059.001"
        ],

        "network_scanning": [
            "T1046"
        ],

        "sql_injection": [
            "T1190"
        ],

        "malicious_download": [
            "T1105"
        ],

        "authentication_success": [
            "T1078"
        ],

        "command_execution": [
            "T1059"
        ],

        "phishing": [
            "T1566"
        ],

        "scheduled_task": [
            "T1053"
        ],

        "startup_persistence": [
            "T1547"
        ]
    }

    # ==========================================================
    # Get Technique
    # ==========================================================

    @classmethod
    def get_technique(
        cls,
        technique_id: str
    ) -> Dict[str, Any]:
        """
        Return information about a MITRE ATT&CK technique.
        """

        technique = cls.TECHNIQUES.get(technique_id)

        if technique is None:
            return {
                "technique_id": technique_id,
                "found": False
            }

        return {
            **technique,
            "found": True
        }

    # ==========================================================
    # Map Event To MITRE
    # ==========================================================

    @classmethod
    def map_event(
        cls,
        event_type: str
    ) -> List[Dict[str, Any]]:
        """
        Map an event type to MITRE ATT&CK techniques.
        """

        technique_ids = cls.EVENT_MAPPING.get(
            event_type,
            []
        )

        results = []

        for technique_id in technique_ids:

            technique = cls.get_technique(
                technique_id
            )

            if technique.get("found"):
                results.append(technique)

        return results

    # ==========================================================
    # Map Multiple Events
    # ==========================================================

    @classmethod
    def map_events(
        cls,
        event_types: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Map multiple event types.
        """

        results = []

        for event_type in event_types:

            techniques = cls.map_event(
                event_type
            )

            results.extend(techniques)

        # Remove duplicates
        unique_results = {}

        for technique in results:

            technique_id = technique["technique_id"]

            unique_results[technique_id] = technique

        return list(unique_results.values())

    # ==========================================================
    # Search By Technique ID
    # ==========================================================

    @classmethod
    def search_technique(
        cls,
        query: str
    ) -> List[Dict[str, Any]]:
        """
        Search techniques by ID, name or tactic.
        """

        query = query.lower().strip()

        results = []

        for technique in cls.TECHNIQUES.values():

            if (
                query in technique["technique_id"].lower()
                or query in technique["name"].lower()
                or query in technique["tactic"].lower()
            ):
                results.append(technique)

        return results

    # ==========================================================
    # Get Mitigations
    # ==========================================================

    @classmethod
    def get_mitigations(
        cls,
        technique_id: str
    ) -> List[str]:
        """
        Return mitigation recommendations.
        """

        technique = cls.TECHNIQUES.get(
            technique_id
        )

        if technique is None:
            return []

        return technique.get(
            "mitigations",
            []
        )

    # ==========================================================
    # Generate MITRE Report
    # ==========================================================

    @classmethod
    def generate_report(
        cls,
        event_type: str
    ) -> Dict[str, Any]:
        """
        Generate a complete MITRE ATT&CK report
        for a detected event.
        """

        techniques = cls.map_event(
            event_type
        )

        return {
            "event_type": event_type,
            "technique_count": len(techniques),
            "techniques": techniques
        }

    # ==========================================================
    # Analyze Processed Log
    # ==========================================================

    @classmethod
    def analyze_log(
        cls,
        processed_log: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Accept output from log_processor.py
        and enrich it with MITRE ATT&CK information.
        """

        event_type = processed_log.get(
            "event_type",
            "unknown"
        )

        techniques = cls.map_event(
            event_type
        )

        processed_log["mitre_attack"] = techniques

        return processed_log