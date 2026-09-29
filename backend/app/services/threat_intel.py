"""
=============================================================
SENTRIX
AI CYBERSECURITY SOC PLATFORM
Threat Intelligence Core
=============================================================

File:
    backend/app/services/threat_intel.py

Purpose:
    Analyze and normalize security indicators for the
    SENTRIX Security Intelligence module.

Supported Indicators:
    - IPv4 / IPv6 addresses
    - Domains
    - URLs
    - MD5 hashes
    - SHA1 hashes
    - SHA256 hashes
    - Email addresses

Features:
    - Indicator validation
    - Indicator normalization
    - Indicator classification
    - Local IOC matching
    - Risk scoring
    - Threat-level classification
    - Confidence calculation
    - SHA256 fingerprint generation
    - Analysis metadata
    - Clean API-ready response

NOTE:
    This is a LOCAL intelligence engine.

    It does NOT claim that an indicator is malicious based
    on internet-wide reputation data.

    External intelligence providers can be integrated later.

=============================================================
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class ThreatIntelService:
    """
    Core Threat Intelligence service used by SENTRIX.
    """

    # =========================================================
    # CONFIGURATION
    # =========================================================

    ENGINE_NAME = "SENTRIX-TI-CORE"
    ENGINE_VERSION = "1.0.0"

    SUPPORTED_TYPES = {
        "ip",
        "domain",
        "url",
        "hash",
        "email",
    }

    HASH_LENGTHS = {
        32: "MD5",
        40: "SHA1",
        64: "SHA256",
    }

    # Local demonstration IOC database.
    #
    # IMPORTANT:
    # These are examples for local testing only.
    # Add your own verified IOCs here or load them from
    # a database/file later.
    LOCAL_IOCS: Dict[str, Dict[str, Any]] = {
        # Example:
        #
        # "example-malicious-domain.com": {
        #     "type": "domain",
        #     "risk_score": 95,
        #     "threat_level": "CRITICAL",
        #     "confidence": "HIGH",
        #     "source": "LOCAL-IOC-DB",
        #     "description": "Known malicious domain"
        # }
    }

    # =========================================================
    # GENERAL HELPERS
    # =========================================================

    @staticmethod
    def _utc_now() -> str:
        """
        Return current UTC timestamp.
        """
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def normalize_indicator(indicator: str) -> str:
        """
        Normalize an indicator before analysis.
        """

        if not isinstance(indicator, str):
            raise ValueError("Indicator must be a string.")

        indicator = indicator.strip()

        if not indicator:
            raise ValueError("Indicator cannot be empty.")

        return indicator

    @staticmethod
    def calculate_fingerprint(indicator: str) -> str:
        """
        Generate SHA256 fingerprint of the normalized indicator.
        """

        return hashlib.sha256(
            indicator.lower().encode("utf-8")
        ).hexdigest()

    # =========================================================
    # IP VALIDATION
    # =========================================================

    @staticmethod
    def validate_ip(indicator: str) -> bool:
        """
        Validate IPv4 or IPv6 address.
        """

        try:
            ipaddress.ip_address(indicator)
            return True

        except ValueError:
            return False

    @staticmethod
    def get_ip_version(indicator: str) -> Optional[str]:
        """
        Return IPv4 or IPv6.
        """

        try:
            address = ipaddress.ip_address(indicator)

            if address.version == 4:
                return "IPv4"

            if address.version == 6:
                return "IPv6"

        except ValueError:
            pass

        return None

    @staticmethod
    def is_private_ip(indicator: str) -> bool:
        """
        Check whether IP belongs to a private network.
        """

        try:
            return ipaddress.ip_address(indicator).is_private

        except ValueError:
            return False

    @staticmethod
    def is_loopback_ip(indicator: str) -> bool:
        """
        Check whether IP is a loopback address.
        """

        try:
            return ipaddress.ip_address(indicator).is_loopback

        except ValueError:
            return False

    # =========================================================
    # DOMAIN VALIDATION
    # =========================================================

    @staticmethod
    def validate_domain(indicator: str) -> bool:
        """
        Validate a domain name.
        """

        if len(indicator) > 253:
            return False

        pattern = (
            r"^(?=.{1,253}$)"
            r"(?!-)"
            r"(?:[A-Za-z0-9]"
            r"(?:[A-Za-z0-9-]{0,61}"
            r"[A-Za-z0-9])?\.)+"
            r"[A-Za-z]{2,63}$"
        )

        return bool(re.fullmatch(pattern, indicator))

    # =========================================================
    # URL VALIDATION
    # =========================================================

    @staticmethod
    def validate_url(indicator: str) -> bool:
        """
        Validate HTTP/HTTPS URL.
        """

        try:
            parsed = urlparse(indicator)

            if parsed.scheme not in {"http", "https"}:
                return False

            if not parsed.netloc:
                return False

            return True

        except Exception:
            return False

    # =========================================================
    # HASH VALIDATION
    # =========================================================

    @classmethod
    def validate_hash(cls, indicator: str) -> bool:
        """
        Validate MD5, SHA1 or SHA256 hash.
        """

        if not re.fullmatch(
            r"[A-Fa-f0-9]+",
            indicator
        ):
            return False

        return len(indicator) in cls.HASH_LENGTHS

    @classmethod
    def get_hash_algorithm(
        cls,
        indicator: str
    ) -> Optional[str]:
        """
        Identify hash algorithm based on length.
        """

        return cls.HASH_LENGTHS.get(
            len(indicator)
        )

    # =========================================================
    # EMAIL VALIDATION
    # =========================================================

    @staticmethod
    def validate_email(indicator: str) -> bool:
        """
        Validate email address format.
        """

        pattern = (
            r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
            r"@"
            r"[A-Za-z0-9-]+"
            r"(?:\.[A-Za-z0-9-]+)+$"
        )

        return bool(
            re.fullmatch(
                pattern,
                indicator
            )
        )

    # =========================================================
    # TYPE VALIDATION
    # =========================================================

    @classmethod
    def validate_indicator(
        cls,
        indicator_type: str,
        indicator: str
    ) -> bool:
        """
        Validate an indicator against the selected type.
        """

        indicator_type = indicator_type.lower().strip()

        if indicator_type not in cls.SUPPORTED_TYPES:
            return False

        if indicator_type == "ip":
            return cls.validate_ip(indicator)

        if indicator_type == "domain":
            return cls.validate_domain(indicator)

        if indicator_type == "url":
            return cls.validate_url(indicator)

        if indicator_type == "hash":
            return cls.validate_hash(indicator)

        if indicator_type == "email":
            return cls.validate_email(indicator)

        return False

    # =========================================================
    # AUTOMATIC TYPE DETECTION
    # =========================================================

    @classmethod
    def detect_indicator_type(
        cls,
        indicator: str
    ) -> str:
        """
        Automatically detect indicator type.
        """

        indicator = indicator.strip()

        if cls.validate_ip(indicator):
            return "ip"

        if cls.validate_url(indicator):
            return "url"

        if cls.validate_hash(indicator):
            return "hash"

        if cls.validate_email(indicator):
            return "email"

        if cls.validate_domain(indicator):
            return "domain"

        return "unknown"

    # =========================================================
    # LOCAL IOC DATABASE
    # =========================================================

    @classmethod
    def lookup_local_ioc(
        cls,
        indicator: str
    ) -> Optional[Dict[str, Any]]:
        """
        Search the local IOC database.
        """

        key = indicator.lower().strip()

        return cls.LOCAL_IOCS.get(key)

    # =========================================================
    # RISK SCORE
    # =========================================================

    @staticmethod
    def classify_risk(
        score: int
    ) -> str:
        """
        Convert numeric score into threat level.
        """

        score = max(
            0,
            min(100, score)
        )

        if score >= 90:
            return "CRITICAL"

        if score >= 70:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def confidence_from_score(
        score: int,
        local_match: bool
    ) -> str:
        """
        Determine confidence level.
        """

        if local_match and score >= 70:
            return "HIGH"

        if local_match:
            return "MEDIUM"

        if score >= 70:
            return "MEDIUM"

        return "LOW"

    # =========================================================
    # LOCAL ANALYSIS
    # =========================================================

    @classmethod
    def perform_local_analysis(
        cls,
        indicator_type: str,
        indicator: str
    ) -> Dict[str, Any]:
        """
        Perform local analysis.

        This function intentionally avoids claiming
        internet reputation information.
        """

        score = 5

        findings: List[str] = []

        local_match = cls.lookup_local_ioc(
            indicator
        )

        # -----------------------------------------------------
        # VERIFIED LOCAL IOC
        # -----------------------------------------------------

        if local_match:

            score = int(
                local_match.get(
                    "risk_score",
                    90
                )
            )

            findings.append(
                "Indicator matched local IOC database."
            )

            return {
                "risk_score": score,
                "threat_level": cls.classify_risk(score),
                "confidence": cls.confidence_from_score(
                    score,
                    True
                ),
                "local_match": True,
                "findings": findings,
                "classification": (
                    "Known Local IOC Match"
                ),
                "sources": [
                    local_match.get(
                        "source",
                        "LOCAL-IOC-DB"
                    )
                ],
            }

        # -----------------------------------------------------
        # IP ANALYSIS
        # -----------------------------------------------------

        if indicator_type == "ip":

            if cls.is_loopback_ip(indicator):

                score = 0

                findings.append(
                    "Loopback IP address detected."
                )

            elif cls.is_private_ip(indicator):

                score = 5

                findings.append(
                    "Private/internal IP address detected."
                )

            else:

                score = 10

                findings.append(
                    "Public IP address format validated."
                )

        # -----------------------------------------------------
        # DOMAIN ANALYSIS
        # -----------------------------------------------------

        elif indicator_type == "domain":

            score = 10

            findings.append(
                "Domain syntax validated successfully."
            )

        # -----------------------------------------------------
        # URL ANALYSIS
        # -----------------------------------------------------

        elif indicator_type == "url":

            parsed = urlparse(indicator)

            score = 10

            findings.append(
                "HTTP/HTTPS URL syntax validated."
            )

            if parsed.scheme == "https":

                findings.append(
                    "HTTPS protocol detected."
                )

            else:

                score += 5

                findings.append(
                    "URL uses HTTP instead of HTTPS."
                )

        # -----------------------------------------------------
        # HASH ANALYSIS
        # -----------------------------------------------------

        elif indicator_type == "hash":

            algorithm = cls.get_hash_algorithm(
                indicator
            )

            score = 10

            findings.append(
                f"{algorithm} hash format detected."
            )

        # -----------------------------------------------------
        # EMAIL ANALYSIS
        # -----------------------------------------------------

        elif indicator_type == "email":

            score = 10

            findings.append(
                "Email address syntax validated."
            )

        # -----------------------------------------------------
        # FINAL LOCAL RESULT
        # -----------------------------------------------------

        threat_level = cls.classify_risk(score)

        return {
            "risk_score": score,
            "threat_level": threat_level,
            "confidence": cls.confidence_from_score(
                score,
                False
            ),
            "local_match": False,
            "findings": findings,
            "classification": "No Local Threat Match",
            "sources": [
                "SENTRIX Local Intelligence Engine"
            ],
        }

    # =========================================================
    # MAIN ANALYSIS FUNCTION
    # =========================================================

    @classmethod
    def analyze(
        cls,
        indicator_type: str,
        indicator: str
    ) -> Dict[str, Any]:
        """
        Main Threat Intelligence analysis function.
        """

        # -----------------------------------------------------
        # BASIC VALIDATION
        # -----------------------------------------------------

        if not indicator_type:

            raise ValueError(
                "Indicator type is required."
            )

        if not indicator:

            raise ValueError(
                "Indicator is required."
            )

        indicator_type = (
            indicator_type
            .strip()
            .lower()
        )

        indicator = cls.normalize_indicator(
            indicator
        )

        # -----------------------------------------------------
        # SUPPORTED TYPE
        # -----------------------------------------------------

        if indicator_type not in cls.SUPPORTED_TYPES:

            raise ValueError(
                "Unsupported indicator type. "
                f"Supported types: "
                f"{', '.join(sorted(cls.SUPPORTED_TYPES))}"
            )

        # -----------------------------------------------------
        # VALIDATE
        # -----------------------------------------------------

        if not cls.validate_indicator(
            indicator_type,
            indicator
        ):

            raise ValueError(
                f"Invalid {indicator_type} indicator format."
            )

        # -----------------------------------------------------
        # NORMALIZATION
        # -----------------------------------------------------

        normalized_indicator = indicator.lower()

        # -----------------------------------------------------
        # LOCAL ANALYSIS
        # -----------------------------------------------------

        local_result = cls.perform_local_analysis(
            indicator_type,
            normalized_indicator
        )

        score = int(
            local_result["risk_score"]
        )

        # -----------------------------------------------------
        # BUILD RESPONSE
        # -----------------------------------------------------

        result: Dict[str, Any] = {

            "success": True,

            "indicator": indicator,

            "normalized_indicator":
                normalized_indicator,

            "indicator_type":
                indicator_type,

            "risk_score":
                score,

            "threat_level":
                local_result["threat_level"],

            "confidence":
                local_result["confidence"],

            "classification":
                local_result["classification"],

            "local_match":
                local_result["local_match"],

            "findings":
                local_result["findings"],

            "sources":
                local_result["sources"],

            "fingerprint":
                cls.calculate_fingerprint(
                    normalized_indicator
                ),

            "analysis_engine":
                cls.ENGINE_NAME,

            "engine_version":
                cls.ENGINE_VERSION,

            "analyzed_at":
                cls._utc_now(),
        }

        # -----------------------------------------------------
        # ADDITIONAL TYPE INFORMATION
        # -----------------------------------------------------

        if indicator_type == "ip":

            result["ip_version"] = (
                cls.get_ip_version(
                    normalized_indicator
                )
            )

            result["private_ip"] = (
                cls.is_private_ip(
                    normalized_indicator
                )
            )

            result["loopback"] = (
                cls.is_loopback_ip(
                    normalized_indicator
                )
            )

        elif indicator_type == "hash":

            result["hash_algorithm"] = (
                cls.get_hash_algorithm(
                    normalized_indicator
                )
            )

        elif indicator_type == "url":

            parsed = urlparse(
                normalized_indicator
            )

            result["url_scheme"] = (
                parsed.scheme
            )

            result["url_host"] = (
                parsed.hostname
            )

            result["url_port"] = (
                parsed.port
            )

        elif indicator_type == "email":

            result["email_domain"] = (
                normalized_indicator
                .split("@", 1)[1]
            )

        return result

    # =========================================================
    # SIMPLE API-FRIENDLY METHOD
    # =========================================================

    @classmethod
    def analyze_auto(
        cls,
        indicator: str
    ) -> Dict[str, Any]:
        """
        Automatically detect indicator type and analyze it.
        """

        indicator = cls.normalize_indicator(
            indicator
        )

        indicator_type = cls.detect_indicator_type(
            indicator
        )

        if indicator_type == "unknown":

            raise ValueError(
                "Unable to determine indicator type."
            )

        return cls.analyze(
            indicator_type,
            indicator
        )


# =============================================================
# SINGLETON INSTANCE
# =============================================================

threat_intel_service = ThreatIntelService()