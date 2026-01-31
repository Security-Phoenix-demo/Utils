#!/usr/bin/env python3
"""
Scanner Translators Module
===========================

Consolidated scanner translator module for Phoenix Multi-Scanner Import Tool.

This module contains all scanner translators organized by category:
- Container Scanners (5)
- Build/SCA Scanners (11)
- Cloud Scanners (5)
- Code/Secret Scanners (8) ✅
- Web Scanners (6) ✅
- Infrastructure Scanners (5) ✅

Total Translators: 42 (consolidated from 76+ original translators)

Key Consolidations (12 major):
- JFrog XRay: 5 variants → 1 translator
- BlackDuck: 7 variants → 1 translator  
- AWS Prowler: 4 variants → 1 translator
- Qualys: 4 variants → 1 translator ✅
- Burp Suite: 3 variants → 1 translator ✅
- Checkmarx: 2 variants → 1 translator ✅
- Tenable: 2 variants → 1 translator ✅
- TruffleHog: 2 variants (3 formats) → 1 translator ✅
- Wiz: 2 variants → 1 translator
- SonarQube: 2 variants → 1 translator
- CycloneDX: 2 variants → 1 translator
- Trivy: 2 variants → 1 translator

Usage:
    from scanner_translators import GrypeTranslator, TrivyTranslator
    # or
    from scanner_translators import *
"""

# Base translator class
from .base_translator import ScannerTranslator, ScannerConfig

# =============================================================================
# CONTAINER SCANNERS (5)
# =============================================================================
from .grype_translator import GrypeTranslator
from .trivy_translator import TrivyTranslator
from .aqua_translator import AquaTranslator
from .sysdig_translator import SysdigTranslator
from .trivy_operator_translator import TrivyOperatorTranslator

# =============================================================================
# BUILD / SCA SCANNERS (11)
# =============================================================================
from .npm_audit_translator import NpmAuditTranslator
from .pip_audit_translator import PipAuditTranslator
from .cyclonedx_translator import CycloneDXTranslator
from .dependency_check_translator import DependencyCheckTranslator
from .snyk_cli_translator import SnykCLITranslator
from .nsp_translator import NSPTranslator
from .snyk_issue_api_translator import SnykIssueAPITranslator
from .ort_translator import ORTTranslator
from .veracode_sca_translator import VeracodeSCACSVTranslator
from .jfrog_xray_translator import JFrogXRayTranslator  # Consolidated 5→1
from .blackduck_translator import BlackDuckTranslator    # Consolidated 5→1

# =============================================================================
# CLOUD SCANNERS (5)
# =============================================================================
from .prowler_translator import ProwlerTranslator        # Consolidated 4→1
from .aws_inspector_translator import AWSInspectorTranslator
from .azure_security_center_translator import AzureSecurityCenterTranslator
from .wiz_translator import WizTranslator                # Consolidated 2→1
from .scout_suite_translator import ScoutSuiteTranslator

# =============================================================================
# CODE / SECRET SCANNERS (8)
# =============================================================================
from .sonarqube_translator import SonarQubeTranslator
from .gitlab_secret_detection_translator import GitLabSecretDetectionTranslator
from .github_secret_scanning_translator import GitHubSecretScanningTranslator
from .noseyparker_translator import NoseyParkerTranslator
from .sarif_translator import SARIFTranslator
from .checkmarx_translator import CheckmarxTranslator      # Consolidated 2→1
from .trufflehog_translator import TruffleHogTranslator    # Consolidated 2→1 (3 formats)
from .fortify_translator import FortifyXMLTranslator
from .kiuwan_translator import KiuwanCSVTranslator

# =============================================================================
# WEB SCANNERS (6)
# =============================================================================
from .testssl_translator import TestSSLTranslator
from .contrast_translator import ContrastTranslator
from .burp_translator import BurpTranslator  # Consolidated 3→1
from .microfocus_webinspect_translator import MicroFocusWebInspectTranslator
from .hackerone_translator import HackerOneCSVTranslator
from .bugcrowd_translator import BugCrowdCSVTranslator
from .solar_appscreener_translator import SolarAppScreenerCSVTranslator

# =============================================================================
# INFRASTRUCTURE SCANNERS (5)
# =============================================================================
from .qualys_translator import QualysTranslator          # Consolidated 4→1
from .tenable_translator import TenableTranslator        # Consolidated 2→1
from .kubeaudit_translator import KubeauditTranslator
from .msdefender_translator import MSDefenderTranslator
from .dsop_translator import DSOPTranslator

# =============================================================================
# PHOENIX & RAPID7 CSV (2) - New native format support
# =============================================================================
from .phoenix_csv_translator import PhoenixCSVTranslator
from .rapid7_csv_translator import Rapid7CSVTranslator

# =============================================================================
# EXPORTS
# =============================================================================
__all__ = [
    # Base
    'ScannerTranslator',
    'ScannerConfig',
    
    # Container (5)
    'GrypeTranslator',
    'TrivyTranslator',
    'AquaTranslator',
    'SysdigTranslator',
    'TrivyOperatorTranslator',
    
    # Build/SCA (11)
    'NpmAuditTranslator',
    'PipAuditTranslator',
    'CycloneDXTranslator',
    'DependencyCheckTranslator',
    'SnykCLITranslator',
    'NSPTranslator',
    'SnykIssueAPITranslator',
    'ORTTranslator',
    'VeracodeSCACSVTranslator',
    'JFrogXRayTranslator',  # 5→1
    'BlackDuckTranslator',  # 5→1
    
    # Cloud (5)
    'ProwlerTranslator',    # 4→1
    'AWSInspectorTranslator',
    'AzureSecurityCenterTranslator',
    'WizTranslator',        # 2→1
    'ScoutSuiteTranslator',
    
    # Code/Secret (8)
    'SonarQubeTranslator',
    'GitLabSecretDetectionTranslator',
    'GitHubSecretScanningTranslator',
    'NoseyParkerTranslator',
    'SARIFTranslator',
    'CheckmarxTranslator',  # 2→1
    'TruffleHogTranslator',  # 2→1 (3 formats)
    'FortifyXMLTranslator',
    'KiuwanCSVTranslator',
    
    # Web (6)
    'TestSSLTranslator',
    'ContrastTranslator',
    'BurpTranslator',  # 3→1
    'MicroFocusWebInspectTranslator',
    'HackerOneCSVTranslator',
    'BugCrowdCSVTranslator',
    'SolarAppScreenerCSVTranslator',
    
    # Infrastructure (5)
    'QualysTranslator',  # 4→1
    'TenableTranslator',  # 2→1
    'KubeauditTranslator',
    'MSDefenderTranslator',
    'DSOPTranslator',
    
    # Phoenix & Rapid7 CSV (2) - Native formats
    'PhoenixCSVTranslator',
    'Rapid7CSVTranslator',
]

# Version info
__version__ = '3.1.0'
__author__ = 'Phoenix Security Team'
__description__ = 'Consolidated Scanner Translators + Phoenix/Rapid7 CSV (44 translators, 12 major consolidations + native CSV support) ✅'
