#!/usr/bin/env python3
"""
Enhanced Phoenix Multi-Scanner Import Tool
Integrates data validation, batching, retry logic, and comprehensive error handling
"""

import argparse
import logging
import os
import sys
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# Defer problematic imports to avoid hanging during module load
# from phoenix_multi_scanner_import import MultiScannerImportManager  # MOVED TO METHODS
# from phoenix_import_enhanced import EnhancedPhoenixImportManager, ImportSession  # MOVED TO METHODS
# from data_validator_enhanced import EnhancedDataValidator  # MOVED TO METHODS
# from phoenix_import_refactored import setup_logging  # MOVED TO METHODS

logger = logging.getLogger(__name__)

class EnhancedMultiScannerImportManager:
    """Enhanced multi-scanner import manager with validation and batching"""
    
    def __init__(self, config_file: str = "config_multi_scanner.ini"):
        # Initialize with minimal setup to avoid hanging
        print(f"🔧 Initializing EnhancedMultiScannerImportManager with config: {config_file}")
        
        try:
            # Import required classes inside the method to avoid module-level hanging
            from phoenix_import_enhanced import EnhancedPhoenixImportManager
            from data_validator_enhanced import EnhancedDataValidator
            from phoenix_import_refactored import PhoenixImportManager
            
            # Initialize base class with lazy translator loading
            self.config_file = config_file
            self.translators = []
            self.scanner_configs = {}
            
            # Initialize flags for asset creation
            self.create_empty_assets = False
            self.create_inventory_assets = False
            
            # Initialize base class components manually to avoid hanging
            PhoenixImportManager.__init__(self, config_file)
            
            # Load configuration manually
            try:
                self.phoenix_config, self.tag_config = self._load_configuration_safe()
                self.config = self.phoenix_config  # For compatibility
                print(f"✅ Loaded Phoenix configuration from {config_file}")
                print(f"   API URL: {self.config.api_base_url}")
            except Exception as e:
                print(f"⚠️ Configuration loading failed: {e}")
                import traceback
                traceback.print_exc()
                raise RuntimeError(f"Failed to load configuration: {e}")
            
            # Ensure API client has configuration
            if hasattr(self, 'api_client') and self.api_client and hasattr(self, 'config') and self.config:
                self.api_client.config = self.config
            
            # Initialize enhanced components
            self.enhanced_importer = EnhancedPhoenixImportManager(config_file)
            self.validator = EnhancedDataValidator()
            
            # Explicitly propagate configuration to enhanced importer and its API client
            self.enhanced_importer.config = self.config
            self.enhanced_importer.phoenix_config = self.phoenix_config
            self.enhanced_importer.tag_config = self.tag_config
            
            # Critical: Ensure API client has the configuration
            if hasattr(self.enhanced_importer, 'api_client') and self.enhanced_importer.api_client:
                self.enhanced_importer.api_client.config = self.config
                print(f"✅ Enhanced importer API client configured with URL: {self.config.api_base_url}")
            else:
                print(f"⚠️ Enhanced importer API client not found or not initialized")
                # Create API client manually if needed
                from phoenix_import_refactored import PhoenixAPIClient
                self.enhanced_importer.api_client = PhoenixAPIClient(self.config)
                print(f"✅ Manually created API client for enhanced importer")
            
            # Copy configuration from enhanced importer - more conservative for high-vulnerability datasets
            self.enhanced_importer.max_payload_size_mb = 15.0  # Even more conservative
            self.enhanced_importer.max_batch_size = 50  # Much smaller batches
            self.enhanced_importer.min_batch_size = 3   # Allow very small batches
            self.enhanced_importer.max_retries = 3
            
            # Defer translator initialization until needed
            self._translators_initialized = False
            
            print("✅ EnhancedMultiScannerImportManager initialized successfully")
            
        except Exception as e:
            print(f"❌ Failed to initialize EnhancedMultiScannerImportManager: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def _load_configuration_safe(self):
        """Safely load configuration without hanging"""
        from phoenix_import_refactored import PhoenixConfig, TagConfig
        import configparser
        import os
        from pathlib import Path
        
        print(f"Loading configuration from {self.config_file}")
        
        # Check if config file exists, try fallbacks
        config_path = Path(self.config_file)
        if not config_path.exists():
            fallback_configs = ["config.ini", "config_multi_scanner EXAMPLE.ini", "config_refactored.ini"]
            for fallback in fallback_configs:
                fallback_path = Path(fallback)
                if fallback_path.exists():
                    print(f"Config not found, using fallback: {fallback}")
                    self.config_file = fallback
                    config_path = fallback_path
                    break
        
        # Load from environment variables first
        phoenix_config = PhoenixConfig(
            client_id=os.getenv('PHOENIX_CLIENT_ID', ''),
            client_secret=os.getenv('PHOENIX_CLIENT_SECRET', ''),
            api_base_url=os.getenv('PHOENIX_API_BASE_URL', ''),
        )
        
        tag_config = TagConfig()
        
        # Load from config file if it exists
        if config_path.exists():
            parser = configparser.ConfigParser()
            parser.read(config_path)
            
            if 'phoenix' in parser:
                section = parser['phoenix']
                if not phoenix_config.client_id:
                    phoenix_config.client_id = section.get('client_id', '')
                if not phoenix_config.client_secret:
                    phoenix_config.client_secret = section.get('client_secret', '')
                if not phoenix_config.api_base_url:
                    phoenix_config.api_base_url = section.get('api_base_url', '')
                
                phoenix_config.scan_type = section.get('scan_type', phoenix_config.scan_type)
                phoenix_config.import_type = section.get('import_type', phoenix_config.import_type)
                phoenix_config.assessment_name = section.get('assessment_name', phoenix_config.assessment_name)
                phoenix_config.scan_target = section.get('scan_target', phoenix_config.scan_target)
                phoenix_config.auto_import = section.getboolean('auto_import', phoenix_config.auto_import)
                phoenix_config.wait_for_completion = section.getboolean('wait_for_completion', phoenix_config.wait_for_completion)
                phoenix_config.batch_delay = section.getint('batch_delay', phoenix_config.batch_delay)
                phoenix_config.timeout = section.getint('timeout', phoenix_config.timeout)
                phoenix_config.check_interval = section.getint('check_interval', phoenix_config.check_interval)
        
        # Validate required configuration
        missing = []
        if not phoenix_config.client_id:
            missing.append('client_id')
        if not phoenix_config.client_secret:
            missing.append('client_secret')
        if not phoenix_config.api_base_url:
            missing.append('api_base_url')
        
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")
        
        return phoenix_config, tag_config
    
    def _ensure_translators_initialized(self):
        """Lazily initialize translators only when needed"""
        if self._translators_initialized:
            return
        
        logger.info("🔧 Initializing translators (lazy loading)...")
        
        try:
            # Import the base class method to initialize translators
            from phoenix_multi_scanner_import import MultiScannerImportManager
            
            # Set up scanner configs
            from phoenix_multi_scanner_import import ScannerConfig
            default_configs = {
                'tenable': ScannerConfig('Tenable Scan', 'INFRA'),
                'qualys': ScannerConfig('Qualys Scan', 'INFRA'),
                'aqua': ScannerConfig('Aqua Scan', 'CONTAINER'),
                'jfrog': ScannerConfig('JFrog Xray Scan', 'BUILD'),
                'sonarqube': ScannerConfig('SonarQube Scan', 'CODE'),
            }
            self.scanner_configs.update(default_configs)
            
            # Initialize translators - Universal translator first, then specific hard-coded ones
            from phoenix_multi_scanner_import import (
                TenableTranslator, QualysTranslator, AquaScanTranslator, AnchoreGrypeTranslator,
                TrivyTranslator, JFrogXrayTranslator, SonarQubeTranslator, ConfigurableScannerTranslator
            )
            
            tag_config = getattr(self, 'tag_config', None)
            if not tag_config:
                from phoenix_import_refactored import TagConfig
                tag_config = TagConfig()
            
            # ═══════════════════════════════════════════════════════════════════════
            # SCANNER TRANSLATORS MODULE v3.0.0 - ALL 42 TRANSLATORS
            # ═══════════════════════════════════════════════════════════════════════
            # All translators migrated to consolidated scanner_translators/ module
            # 12 major consolidations completed | 76+ → 42 translators
            
            # Container Scanners (5)
            from scanner_translators import (
                GrypeTranslator,
                TrivyTranslator,              # Consolidated 2→1
                AquaTranslator,
                SysdigTranslator,
                TrivyOperatorTranslator
            )
            
            # Build/SCA Scanners (11 - includes major consolidations)
            from scanner_translators import (
                NpmAuditTranslator,
                PipAuditTranslator,
                CycloneDXTranslator,          # Consolidated 2→1
                DependencyCheckTranslator,
                SnykCLITranslator,
                NSPTranslator,
                SnykIssueAPITranslator,
                ORTTranslator,
                VeracodeSCACSVTranslator,
                JFrogXRayTranslator,          # Consolidated 5→1 🔥
                BlackDuckTranslator,          # Consolidated 7→1 🔥
                DSOPTranslator                # 🆕
            )
            
            # Cloud Scanners (5 - includes major consolidations)
            from scanner_translators import (
                ProwlerTranslator,            # Consolidated 4→1 🔥
                AWSInspectorTranslator,
                AzureSecurityCenterTranslator,
                WizTranslator,                # Consolidated 2→1
                ScoutSuiteTranslator
            )
            
            # Code/Secret Scanners (8)
            from scanner_translators import (
                SonarQubeTranslator,          # Consolidated 2→1
                GitLabSecretDetectionTranslator,
                GitHubSecretScanningTranslator,
                NoseyParkerTranslator,
                SARIFTranslator,
                CheckmarxTranslator,          # Consolidated 2→1 🆕
                TruffleHogTranslator,         # Consolidated 2→1 (3 formats) 🆕
                FortifyXMLTranslator,         # 🆕
                KiuwanCSVTranslator           # 🆕
            )
            
            # Web Scanners (6)
            from scanner_translators import (
                TestSSLTranslator,
                ContrastTranslator,
                BurpTranslator,               # Consolidated 3→1 🆕
                MicroFocusWebInspectTranslator, # 🆕
                HackerOneCSVTranslator,       # 🆕
                BugCrowdCSVTranslator,        # 🆕
                SolarAppScreenerCSVTranslator # 🆕
            )
            
            # Infrastructure Scanners (5)
            from scanner_translators import (
                QualysTranslator,             # Consolidated 4→1 🆕
                TenableTranslator,            # Consolidated 2→1 🆕
                KubeauditTranslator,          # 🆕
                MSDefenderTranslator,         # 🆕
                DSOPTranslator                # 🆕 (duplicate in Build for flexibility)
            )
            
            # Additional Format Handlers
            from format_handlers import ChefInspecTranslator
            
            # Add scanner config for Grype, Trivy, JFrog, BlackDuck, Prowler, Tier1, Tier2, Tier3, SARIF, Format Handlers, and Universal
            from phoenix_multi_scanner_import import ScannerConfig
            self.scanner_configs['anchore_grype'] = ScannerConfig('Anchore Grype Scan', 'CONTAINER')
            self.scanner_configs['trivy'] = ScannerConfig('Trivy Scan', 'CONTAINER')
            self.scanner_configs['jfrog'] = ScannerConfig('JFrog XRay', 'BUILD')
            self.scanner_configs['blackduck'] = ScannerConfig('BlackDuck', 'BUILD')
            self.scanner_configs['prowler'] = ScannerConfig('AWS Prowler', 'CLOUD')
            self.scanner_configs['aws_prowler'] = self.scanner_configs['prowler']  # Alias
            self.scanner_configs['aws_prowler_v2'] = ScannerConfig('AWS Prowler v2', 'CLOUD')
            self.scanner_configs['aws_prowler_v3'] = ScannerConfig('AWS Prowler v3', 'CLOUD')
            self.scanner_configs['aws_prowler_v4'] = ScannerConfig('AWS Prowler v4/v5', 'CLOUD')
            self.scanner_configs['aws_prowler_v5'] = self.scanner_configs['aws_prowler_v4']  # V5 uses V4 translator
            self.scanner_configs['tenable'] = ScannerConfig('Tenable Nessus', 'INFRA')
            self.scanner_configs['dependency_check'] = ScannerConfig('OWASP Dependency Check', 'BUILD')
            self.scanner_configs['sonarqube'] = ScannerConfig('SonarQube', 'CODE')
            self.scanner_configs['cyclonedx'] = ScannerConfig('CycloneDX SBOM', 'BUILD')
            self.scanner_configs['npm_audit'] = ScannerConfig('npm audit', 'BUILD')
            self.scanner_configs['pip_audit'] = ScannerConfig('pip-audit', 'BUILD')
            self.scanner_configs['qualys_webapp'] = ScannerConfig('Qualys WebApp', 'WEB')
            self.scanner_configs['burp_api'] = ScannerConfig('Burp Suite API', 'WEB')
            self.scanner_configs['burp'] = ScannerConfig('Burp Suite XML', 'WEB')
            self.scanner_configs['checkmarx_osa'] = ScannerConfig('Checkmarx OSA', 'BUILD')
            self.scanner_configs['checkmarx'] = ScannerConfig('Checkmarx CxSAST XML', 'CODE')
            self.scanner_configs['qualys'] = ScannerConfig('Qualys VM/WebApp XML', 'INFRA')
            self.scanner_configs['snyk_issue_api'] = ScannerConfig('Snyk Issues API', 'BUILD')
            self.scanner_configs['sarif'] = ScannerConfig('SARIF Universal', 'CODE')
            self.scanner_configs['chefinspect'] = ScannerConfig('Chef InSpec', 'INFRA')
            self.scanner_configs['scout_suite'] = ScannerConfig('Scout Suite', 'CLOUD')
            self.scanner_configs['kubeaudit'] = ScannerConfig('Kubeaudit', 'CONTAINER')
            self.scanner_configs['nsp'] = ScannerConfig('NSP (Node Security Project)', 'BUILD')
            self.scanner_configs['snyk_cli'] = ScannerConfig('Snyk CLI', 'BUILD')
            self.scanner_configs['api_sonarqube'] = ScannerConfig('SonarQube API', 'CODE')
            self.scanner_configs['aws_inspector2'] = ScannerConfig('AWS Inspector v2', 'CLOUD')
            self.scanner_configs['aws_prowler_csv'] = ScannerConfig('AWS Prowler CSV', 'CLOUD')
            self.scanner_configs['microfocus_webinspect'] = ScannerConfig('MicroFocus WebInspect', 'WEB')
            self.scanner_configs['trufflehog'] = ScannerConfig('TruffleHog Secrets Scanner', 'CODE')
            self.scanner_configs['jfrogxray_simple'] = ScannerConfig('JFrog XRay Simple', 'BUILD')
            self.scanner_configs['trufflehog3'] = ScannerConfig('TruffleHog v3', 'CODE')
            self.scanner_configs['contrast'] = ScannerConfig('Contrast Security', 'WEB')
            self.scanner_configs['qualys_vm'] = ScannerConfig('Qualys VM', 'INFRA')
            self.scanner_configs['blackduck_binary_csv'] = ScannerConfig('BlackDuck Binary Analysis', 'BUILD')
            self.scanner_configs['noseyparker'] = ScannerConfig('NoseyParker Secrets', 'CODE')
            self.scanner_configs['dsop'] = ScannerConfig('DSOP', 'INFRA')
            self.scanner_configs['blackduck_component_risk'] = ScannerConfig('BlackDuck Component Risk', 'BUILD')
            self.scanner_configs['burp_suite_dast'] = ScannerConfig('Burp Suite DAST', 'WEB')
            self.scanner_configs['blackduck_standard'] = ScannerConfig('BlackDuck Standard', 'BUILD')
            self.scanner_configs['trivy_operator'] = ScannerConfig('Trivy Operator', 'CONTAINER')
            self.scanner_configs['qualys_csv'] = ScannerConfig('Qualys CSV', 'INFRA')
            self.scanner_configs['bugcrowd_csv'] = ScannerConfig('BugCrowd', 'WEB')
            self.scanner_configs['azure_csv'] = ScannerConfig('Azure Security Center', 'CLOUD')
            self.scanner_configs['kiuwan_csv'] = ScannerConfig('Kiuwan', 'CODE')
            self.scanner_configs['wiz_csv'] = ScannerConfig('Wiz', 'CLOUD')
            self.scanner_configs['veracode_sca_csv'] = ScannerConfig('Veracode SCA', 'BUILD')
            self.scanner_configs['sysdig_csv'] = ScannerConfig('Sysdig', 'CONTAINER')
            self.scanner_configs['solar_csv'] = ScannerConfig('Solar appScreener', 'WEB')
            self.scanner_configs['ms_defender'] = ScannerConfig('Microsoft Defender', 'INFRA')
            self.scanner_configs['ort'] = ScannerConfig('OSS Review Toolkit', 'BUILD')
            self.scanner_configs['gitlab_secret'] = ScannerConfig('GitLab Secret Detection', 'CODE')
            self.scanner_configs['testssl'] = ScannerConfig('TestSSL', 'WEB')
            self.scanner_configs['github_secret'] = ScannerConfig('GitHub Secret Scanning', 'CODE')
            self.scanner_configs['h1'] = ScannerConfig('HackerOne', 'WEB')
            self.scanner_configs['wiz_issues'] = ScannerConfig('Wiz Issues', 'CLOUD')
            self.scanner_configs['fortify'] = ScannerConfig('Fortify', 'CODE')
            self.scanner_configs['universal'] = ScannerConfig('Universal YAML-Based Scanner', 'INFRA')
            
            logger.info("🔧 Initializing translators (HYBRID mode: Specialized hard-coded + YAML fallback)...")
            
            # ═══════════════════════════════════════════════════════════════════════
            # TRANSLATOR INSTANTIATION - All 42 Consolidated Translators v3.0.0
            # ═══════════════════════════════════════════════════════════════════════
            self.translators = [
                # CONTAINER SCANNERS (5)
                GrypeTranslator(self.scanner_configs.get('anchore_grype', {}), tag_config),
                TrivyTranslator(self.scanner_configs.get('trivy', {}), tag_config),                  # 2→1
                AquaTranslator(self.scanner_configs.get('aqua', {}), tag_config),
                SysdigTranslator(self.scanner_configs.get('sysdig_csv', {}), tag_config),
                TrivyOperatorTranslator(self.scanner_configs.get('trivy_operator', {}), tag_config),
                
                # BUILD/SCA SCANNERS (11 - includes major consolidations)
                NpmAuditTranslator(self.scanner_configs.get('npm_audit', {}), tag_config),
                PipAuditTranslator(self.scanner_configs.get('pip_audit', {}), tag_config),
                CycloneDXTranslator(self.scanner_configs.get('cyclonedx', {}), tag_config),          # 2→1
                DependencyCheckTranslator(self.scanner_configs.get('dependency_check', {}), tag_config),
                SnykCLITranslator(self.scanner_configs.get('snyk_cli', {}), tag_config),
                NSPTranslator(self.scanner_configs.get('nsp', {}), tag_config),
                SnykIssueAPITranslator(self.scanner_configs.get('snyk_issue_api', {}), tag_config),
                ORTTranslator(self.scanner_configs.get('ort', {}), tag_config),
                VeracodeSCACSVTranslator(self.scanner_configs.get('veracode_sca_csv', {}), tag_config),
                JFrogXRayTranslator(self.scanner_configs.get('jfrog', {}), tag_config),              # 5→1 🔥
                BlackDuckTranslator(self.scanner_configs.get('blackduck', {}), tag_config),          # 7→1 🔥
                DSOPTranslator(self.scanner_configs.get('dsop', {}), tag_config),
                
                # CLOUD SCANNERS (5 - includes major consolidations)
                ProwlerTranslator(self.scanner_configs.get('aws_prowler_v2', {}), tag_config),       # 4→1 🔥
                AWSInspectorTranslator(self.scanner_configs.get('aws_inspector2', {}), tag_config),
                AzureSecurityCenterTranslator(self.scanner_configs.get('azure_csv', {}), tag_config),
                WizTranslator(self.scanner_configs.get('wiz_csv', {}), tag_config),                  # 2→1
                ScoutSuiteTranslator(self.scanner_configs.get('scout_suite', {}), tag_config),
                
                # CODE/SECRET SCANNERS (8)
                SonarQubeTranslator(self.scanner_configs.get('sonarqube', {}), tag_config),          # 2→1
                GitLabSecretDetectionTranslator(self.scanner_configs.get('gitlab_secret', self.scanner_configs.get('gitlab_secret_detection', {})), tag_config),
                GitHubSecretScanningTranslator(self.scanner_configs.get('github_secret', self.scanner_configs.get('github_secret_scanning', {})), tag_config),
                NoseyParkerTranslator(self.scanner_configs.get('noseyparker', {}), tag_config),
                SARIFTranslator(self.scanner_configs.get('sarif', {}), tag_config),
                CheckmarxTranslator(self.scanner_configs.get('checkmarx', {}), tag_config),          # 2→1 🆕
                TruffleHogTranslator(self.scanner_configs.get('trufflehog', {}), tag_config),        # 2→1 (3 formats) 🆕
                FortifyXMLTranslator(self.scanner_configs.get('fortify', {}), tag_config),           # 🆕
                KiuwanCSVTranslator(self.scanner_configs.get('kiuwan_csv', {}), tag_config),         # 🆕
                
                # WEB SCANNERS (6)
                TestSSLTranslator(self.scanner_configs.get('testssl', {}), tag_config),
                ContrastTranslator(self.scanner_configs.get('contrast', {}), tag_config),
                BurpTranslator(self.scanner_configs.get('burp', {}), tag_config),                    # 3→1 🆕
                MicroFocusWebInspectTranslator(self.scanner_configs.get('microfocus_webinspect', {}), tag_config),  # 🆕
                HackerOneCSVTranslator(self.scanner_configs.get('h1', {}), tag_config),              # 🆕
                BugCrowdCSVTranslator(self.scanner_configs.get('bugcrowd_csv', {}), tag_config),     # 🆕
                SolarAppScreenerCSVTranslator(self.scanner_configs.get('solar_csv', {}), tag_config), # 🆕
                
                # INFRASTRUCTURE SCANNERS (5)
                QualysTranslator(self.scanner_configs.get('qualys', {}), tag_config),                # 4→1 🆕
                TenableTranslator(self.scanner_configs.get('tenable', {}), tag_config),              # 2→1 🆕
                KubeauditTranslator(self.scanner_configs.get('kubeaudit', {}), tag_config),          # 🆕
                MSDefenderTranslator(self.scanner_configs.get('ms_defender', {}), tag_config),       # 🆕
                DSOPTranslator(self.scanner_configs.get('dsop', {}), tag_config),                    # 🆕 (duplicate for flexibility)
                
                # ADDITIONAL FORMAT HANDLERS
                ChefInspecTranslator(self.scanner_configs.get('chefinspect', {}), tag_config),
                
                # UNIVERSAL YAML FALLBACK - scanner_field_mappings.yaml (200+ scanner types)
                ConfigurableScannerTranslator(
                    self.scanner_configs.get('universal', {}), 
                    tag_config,
                    self.create_empty_assets,
                    self.create_inventory_assets
                ),
            ]
            
            self._translators_initialized = True
            logger.info(f"✅ Initialized {len(self.translators)} translators v3.0.0 (MIGRATION COMPLETE: 12 major consolidations | Container[5] + Build[11] + Cloud[5] + Code/Secret[8] + Web[6] + Infrastructure[5] + Format Handlers[2] | 76+ → 42 translators + YAML fallback)")
            
        except Exception as e:
            logger.error(f"❌ CRITICAL: Failed to initialize YAML-based translator: {e}")
            import traceback
            traceback.print_exc()
            # NO FALLBACK - Using YAML-only approach per user requirements
            logger.error("❌ Hard-coded translators are disabled. Please fix scanner_field_mappings.yaml")
            self.translators = []
            self._translators_initialized = True
            raise RuntimeError(f"Failed to initialize YAML translator: {e}")
    
    def _find_translator_by_name(self, scanner_name: str):
        """Find translator by scanner name (e.g., 'anchore_grype', 'trivy')"""
        self._ensure_translators_initialized()
        
        scanner_name_lower = scanner_name.lower().replace('-', '_').replace(' ', '_')
        
        # Map of scanner names to translator class name patterns
        name_mappings = {
            'anchore_grype': 'AnchoreGrypeTranslator',
            'grype': 'AnchoreGrypeTranslator',
            'trivy': 'TrivyTranslator',
            'aqua': 'AquaScanTranslator',
            'jfrog': 'JFrogXRayAPISummaryArtifactTranslator',
            'blackduck': 'BlackDuckBinaryAnalysisTranslator',
            'prowler': 'AWSProwlerV2Translator',  # Default to V2 for backward compatibility
            'aws_prowler': 'AWSProwlerV2Translator',  # Alias
            'aws_prowler_v3plus': 'AWSProwlerV4Translator',  # V3+ uses V4 translator (OCSF)
            'tenable': 'TenableNessusTranslator',
            'dependency_check': 'DependencyCheckTranslator',
            'sonarqube': 'SonarQubeTranslator',
            'cyclonedx': 'CycloneDXTranslator',
            'npm_audit': 'NpmAuditTranslator',
            'pip_audit': 'PipAuditTranslator',
            'qualys_webapp': 'QualysWebAppTranslator',
            'qualys': 'QualysXMLTranslator',  # XML format (VM/WebApp)
            'burp_api': 'BurpAPITranslator',
            'burp': 'BurpXMLTranslator',  # XML format
            'checkmarx_osa': 'CheckmarxOSATranslator',
            'checkmarx': 'CheckmarxXMLTranslator',  # CxSAST XML format
            'snyk_issue_api': 'SnykIssueAPITranslator',
            'sarif': 'SARIFTranslator',
            'chefinspect': 'ChefInspecTranslator',
            'scout_suite': 'ScoutSuiteTranslator',
            'kubeaudit': 'KubeauditTranslator',
            'nsp': 'NSPTranslator',
            'snyk_cli': 'SnykCLITranslator',
            'snyk': 'SnykCLITranslator',  # Alias for backward compatibility
            'api_sonarqube': 'SonarQubeAPITranslator',
            'aws_inspector2': 'AWSInspector2Translator',
            'aws_prowler': 'AWSProwlerCSVTranslator',  # CSV format for V2
            'microfocus_webinspect': 'MicroFocusWebInspectTranslator',
            'trufflehog': 'TruffleHogTranslator',
            'jfrogxray': 'JFrogXRaySimpleTranslator',  # Simple format
            'trufflehog3': 'TruffleHog3Translator',
            'contrast': 'ContrastTranslator',
            'qualys_vm': 'QualysVMTranslator',  # VM XML format
            'blackduck_binary_analysis': 'BlackDuckBinaryCSVTranslator',
            'noseyparker': 'NoseyParkerTranslator',
            'dsop': 'DSOPTranslator',
            'blackduck_component_risk': 'BlackDuckComponentRiskTranslator',
            'burp_suite_dast': 'BurpSuiteDASTTranslator',
            'blackduck': 'BlackDuckStandardZIPTranslator',
            'trivy_operator': 'TrivyOperatorTranslator',
            'qualys': 'QualysCSVTranslator',  # Prioritize CSV over XML
            'bugcrowd': 'BugCrowdCSVTranslator',
            'azure_security_center_recommendations': 'AzureSecurityCenterCSVTranslator',
            'kiuwan': 'KiuwanCSVTranslator',
            'wiz': 'WizCSVTranslator',
            'veracode_sca': 'VeracodeSCACSVTranslator',
            'sysdig_cli': 'SysdigCSVTranslator',
            'sysdig_reports': 'SysdigCSVTranslator',
            'solar_appscreener': 'SolarAppScreenerCSVTranslator',
            'ms_defender': 'MSDefenderTranslator',
            'ort': 'ORTTranslator',
            'gitlab_secret_detection_report': 'GitLabSecretDetectionTranslator',
            'testssl': 'TestSSLTranslator',
            'github_secrets_detection_report': 'GitHubSecretDetectionTranslator',
            'h1': 'HackerOneCSVTranslator',
            'wiz': 'WizIssuesCSVTranslator',  # Prioritize Issues format
            'fortify': 'FortifyXMLTranslator',
        }
        
        # First try exact match in mappings
        if scanner_name_lower in name_mappings:
            target_class_name = name_mappings[scanner_name_lower]
            for translator in self.translators:
                if translator.__class__.__name__ == target_class_name:
                    logger.info(f"✅ Found hard-coded translator: {target_class_name}")
                    return translator
        
        # Then try partial match in translator class name
        for translator in self.translators:
            translator_name = translator.__class__.__name__.lower()
            if scanner_name_lower in translator_name or translator_name.replace('translator', '') in scanner_name_lower:
                logger.info(f"✅ Found translator by partial match: {translator.__class__.__name__}")
                return translator
        
        return None
    
    def detect_scanner_type(self, file_path: str):
        """Detect scanner type with lazy translator initialization, ensuring absolute path for file operations"""
        # Convert to absolute path if relative
        if not os.path.isabs(file_path):
            file_path = os.path.abspath(file_path)
            logger.debug(f"Converted to absolute path: {file_path}")
        
        self._ensure_translators_initialized()
        
        # Try each translator
        for translator in self.translators:
            try:
                if translator.can_handle(file_path):
                    return translator
            except Exception as e:
                logger.debug(f"Translator {translator.__class__.__name__} failed to check file: {e}")
        
        return None
    
    def process_scanner_file_enhanced(self, file_path: str, scanner_type: Optional[str] = None,
                                    asset_type: Optional[str] = None, assessment_name: Optional[str] = None,
                                    import_type: str = "delta", anonymize: bool = False,
                                    just_tags: bool = False, create_empty_assets: bool = False,
                                    create_inventory_assets: bool = False, verify_import: bool = False,
                                    enable_batching: bool = True, fix_data: bool = True) -> Dict[str, Any]:
        """Enhanced file processing with validation, fixing, and batching"""
        
        logger.info(f"🚀 Enhanced processing: {file_path}")
        logger.info(f"   Scanner: {scanner_type or 'auto-detect'}")
        logger.info(f"   Asset Type: {asset_type or 'auto-detect'}")
        logger.info(f"   Batching: {'enabled' if enable_batching else 'disabled'}")
        logger.info(f"   Data Fixing: {'enabled' if fix_data else 'disabled'}")
        
        try:
            # Step 1: Try to detect scanner type with original file (important for CSV)
            processed_file_path = file_path
            skip_csv_fix = False
            
            if scanner_type and scanner_type != 'auto':
                # SCANNER TYPE SPECIFIED - Use it directly (takes priority over auto-detect)
                detected_scanner = str(scanner_type).lower()
                logger.info(f"✅ Using specified scanner type: {detected_scanner}")
                # Find translator for this scanner type
                translator = self._find_translator_by_name(detected_scanner)
                if not translator:
                    logger.warning(f"⚠️ No hard-coded translator found for '{detected_scanner}', using YAML fallback")
                    translator = self.detect_scanner_type(file_path)
            else:
                # AUTO-DETECT MODE (fallback only if scanner not specified)
                logger.info("🔍 Auto-detecting scanner type...")
                # Try detection on original file first
                translator = self.detect_scanner_type(file_path)
                
                if translator:
                    # Found a translator for original file - skip CSV fixing
                    detected_scanner = translator.__class__.__name__.replace('Translator', '').lower()
                    logger.info(f"🔍 Detected scanner type: {detected_scanner}")
                    skip_csv_fix = True
                elif fix_data and file_path.lower().endswith('.csv'):
                    # No translator found, try CSV fixing
                    logger.info("🔧 No hard-coded translator found, attempting CSV data fixing...")
                    processed_file_path = self._fix_csv_data(file_path)
                    translator = self.detect_scanner_type(processed_file_path)
                    if translator:
                        detected_scanner = translator.__class__.__name__.replace('Translator', '').lower()
                        logger.info(f"🔍 Detected scanner type after CSV fix: {detected_scanner}")
                
                if not translator:
                    return {
                        'success': False,
                        'error': f'Could not detect scanner type for {file_path}',
                        'file_path': file_path
                    }
            
            # Step 3: Parse file to assets (pass translator object directly)
            assets = self._parse_file_to_assets(processed_file_path, translator, asset_type)
            
            if not assets:
                return {
                    'success': False,
                    'error': 'No assets parsed from file',
                    'file_path': file_path
                }
            
            logger.info(f"📋 Parsed {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
            
            # Step 4: Handle tags-only mode
            if just_tags:
                return self._process_tags_only(assets, file_path)
            
            # Step 5: Generate assessment name if not provided
            if not assessment_name:
                assessment_name = self._generate_assessment_name(file_path, detected_scanner)
            
            # Step 6: Import with or without batching
            if enable_batching:
                session = self.enhanced_importer.import_assets_with_batching(
                    assets, assessment_name, import_type, validate_data=True
                )
                return self._convert_session_to_result(session, file_path, detected_scanner, assessment_name)
            else:
                # Traditional single-request import using API client
                from phoenix_import_refactored import PhoenixAPIClient
                api_client = PhoenixAPIClient(self.phoenix_config)
                result = api_client.import_assets(assets, assessment_name)
                return {
                    'success': True,
                    'file_path': file_path,
                    'scanner_type': detected_scanner,
                    'assessment_name': assessment_name,
                    'assets_imported': len(assets),
                    'vulnerabilities_imported': sum(len(a.findings) for a in assets),
                    'import_type': import_type,
                    'request_id': result.get('request_id'),
                    'batching_used': False
                }
            
        except Exception as e:
            logger.error(f"❌ Enhanced processing failed for {file_path}: {e}")
            logger.debug(traceback.format_exc())
            return {
                'success': False,
                'error': str(e),
                'file_path': file_path,
                'scanner_type': scanner_type
            }
    
    def _fix_csv_data(self, file_path: str) -> str:
        """Fix CSV data issues and return path to fixed file"""
        logger.info(f"🔧 Fixing CSV data: {file_path}")
        
        # Generate fixed file path
        file_path_obj = Path(file_path)
        fixed_file_path = str(file_path_obj.parent / f"{file_path_obj.stem}_fixed{file_path_obj.suffix}")
        
        # Validate and fix
        validation_result = self.validator.validate_and_fix_csv(file_path, fixed_file_path)
        
        if validation_result.issues:
            logger.info(f"📋 Data fixing results:")
            logger.info(f"   Issues found: {len(validation_result.issues)}")
            
            # Log issue summary
            by_severity = {}
            for issue in validation_result.issues:
                if issue.severity not in by_severity:
                    by_severity[issue.severity] = 0
                by_severity[issue.severity] += 1
            
            for severity, count in by_severity.items():
                logger.info(f"   {severity}: {count}")
        
        # Check if we should use the fixed file
        if Path(fixed_file_path).exists():
            logger.info(f"✅ Using fixed file: {fixed_file_path}")
            return fixed_file_path
        else:
            logger.warning(f"⚠️ Fixed file not created, using original: {file_path}")
            return file_path
    
    def _parse_file_to_assets(self, file_path: str, translator_or_name, asset_type: Optional[str]):
        """Parse file to assets using appropriate translator
        
        Args:
            file_path: Path to file to parse
            translator_or_name: Either a translator object or scanner name string
            asset_type: Optional asset type override
        """
        
        # Convert to absolute path if relative (for translator access)
        if not os.path.isabs(file_path):
            file_path = os.path.abspath(file_path)
            logger.debug(f"Converted file path to absolute: {file_path}")
        
        # Check if we received a translator object directly
        from phoenix_multi_scanner_import import ScannerTranslator
        if isinstance(translator_or_name, ScannerTranslator):
            # Use the provided translator directly
            translator = translator_or_name
            logger.debug(f"Using provided translator: {translator.__class__.__name__}")
        else:
            # Legacy path: translator name provided, need to find it
            scanner_type_str = str(translator_or_name).lower() if translator_or_name else ''
            
            # Normalize scanner type for better matching
            scanner_normalized = scanner_type_str.replace('_scan', '').replace('_', '').replace(' ', '')
            
            # Find the appropriate translator
            translator = None
            for t in self.translators:
                class_name_normalized = t.__class__.__name__.lower().replace('translator', '')
                
                # Try exact match first
                if class_name_normalized.startswith(scanner_normalized):
                    translator = t
                    logger.debug(f"Matched translator {t.__class__.__name__} for scanner type {translator_or_name}")
                    break
                
                # Try partial match for backward compatibility
                if 'prowler' in scanner_normalized and 'prowler' in class_name_normalized:
                    translator = t
                    logger.debug(f"Partial matched translator {t.__class__.__name__} for scanner type {translator_or_name}")
                    break
                
                # Special case: v5 should use v4 translator
                if 'prowlerv5' in scanner_normalized and 'prowlerv4' in class_name_normalized:
                    translator = t
                    logger.debug(f"V5 matched to V4 translator {t.__class__.__name__} for scanner type {translator_or_name}")
                    break
            
            if not translator:
                # Fallback to auto-detection
                logger.debug(f"No translator matched for '{translator_or_name}', trying auto-detection")
                translator = self.detect_scanner_type(file_path)
            
            if not translator:
                raise ValueError(f"No suitable translator found for scanner type: {translator_or_name}")
        
        # Parse the file
        assets = translator.parse_file(file_path)
        
        # Override asset type if specified
        if asset_type:
            for asset in assets:
                asset.asset_type = asset_type
        
        return assets
    
    def _process_tags_only(self, assets: List, file_path: str) -> Dict[str, Any]:
        """Process tags-only mode"""
        logger.info(f"🏷️ Processing tags-only mode for {len(assets)} assets")
        
        # Apply tags to assets
        tags_applied = 0
        for asset in assets:
            if hasattr(asset, 'tags') and asset.tags:
                tags_applied += len(asset.tags)
        
        return {
            'success': True,
            'file_path': file_path,
            'assets_tagged': len(assets),
            'tags_applied': tags_applied,
            'just_tags': True
        }
    
    def _generate_assessment_name(self, file_path: str, scanner_type: str) -> str:
        """Generate assessment name from file and scanner info"""
        file_name = Path(file_path).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        return f"{scanner_type.upper()}-{file_name}-{timestamp}"
    
    def _convert_session_to_result(self, session: Any, file_path: str, 
                                 scanner_type: str, assessment_name: str) -> Dict[str, Any]:
        """Convert ImportSession to result dictionary"""
        
        successful_batches = [r for r in session.batch_results if r.success]
        failed_batches = [r for r in session.batch_results if not r.success]
        
        total_assets = sum(r.assets_processed for r in successful_batches)
        total_vulnerabilities = sum(r.vulnerabilities_processed for r in successful_batches)
        
        result = {
            'success': session.success_rate >= 80.0,  # Consider 80%+ success rate as successful
            'file_path': file_path,
            'scanner_type': scanner_type,
            'assessment_name': assessment_name,
            'assets_imported': total_assets,
            'vulnerabilities_imported': total_vulnerabilities,
            'import_type': 'batched',
            'batching_used': True,
            'session_id': session.session_id,
            'batch_summary': {
                'total_batches': session.total_batches,
                'successful_batches': session.completed_batches,
                'failed_batches': session.failed_batches,
                'success_rate': session.success_rate
            }
        }
        
        # Add request IDs from successful batches
        request_ids = [r.request_id for r in successful_batches if r.request_id]
        if request_ids:
            result['request_ids'] = request_ids
            result['request_id'] = request_ids[0]  # For compatibility
        
        # Add error details for failed batches
        if failed_batches:
            result['batch_errors'] = [
                {
                    'batch_number': r.batch_number,
                    'error': r.error_message,
                    'retry_count': r.retry_count
                }
                for r in failed_batches
            ]
        
        return result
    
    def process_folder_enhanced(self, folder_path: str, file_types: List[str] = None,
                              scanner_type: Optional[str] = None, asset_type: Optional[str] = None,
                              import_type: str = "new", anonymize: bool = False,
                              just_tags: bool = False, create_empty_assets: bool = False,
                              create_inventory_assets: bool = False, enable_batching: bool = True,
                              fix_data: bool = True) -> Dict[str, Any]:
        """Enhanced folder processing with validation and batching"""
        
        if file_types is None:
            file_types = ['json', 'csv', 'xml']
        
        folder_path_obj = Path(folder_path)
        if not folder_path_obj.exists():
            raise ValueError(f"Folder does not exist: {folder_path}")
        
        # Find all matching files
        files_to_process = []
        for file_type in file_types:
            pattern = f"*.{file_type}"
            files_to_process.extend(folder_path_obj.glob(pattern))
        
        if not files_to_process:
            return {
                'success': False,
                'error': f'No files found with extensions: {file_types}',
                'folder_path': folder_path
            }
        
        logger.info(f"📁 Processing folder: {folder_path}")
        logger.info(f"   Found {len(files_to_process)} files to process")
        
        # Process each file
        results = []
        successful_files = 0
        failed_files = 0
        
        for file_path in files_to_process:
            logger.info(f"🔄 Processing file: {file_path.name}")
            
            try:
                result = self.process_scanner_file_enhanced(
                    str(file_path),
                    scanner_type=scanner_type,
                    asset_type=asset_type,
                    import_type=import_type,
                    anonymize=anonymize,
                    just_tags=just_tags,
                    create_empty_assets=create_empty_assets,
                    create_inventory_assets=create_inventory_assets,
                    enable_batching=enable_batching,
                    fix_data=fix_data
                )
                
                results.append(result)
                
                if result['success']:
                    successful_files += 1
                    logger.info(f"✅ {file_path.name}")
                else:
                    failed_files += 1
                    logger.error(f"❌ {file_path.name}: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                failed_files += 1
                error_result = {
                    'success': False,
                    'file_path': str(file_path),
                    'error': str(e)
                }
                results.append(error_result)
                logger.error(f"❌ {file_path.name}: {str(e)}")
        
        # Summary
        logger.info(f"📊 Folder processing complete:")
        logger.info(f"   Total files: {len(files_to_process)}")
        logger.info(f"   ✅ Successful: {successful_files}")
        logger.info(f"   ❌ Failed: {failed_files}")
        
        return {
            'success': failed_files == 0,
            'folder_path': folder_path,
            'total_files': len(files_to_process),
            'successful_files': successful_files,
            'failed_files': failed_files,
            'results': results
        }

def main():
    """Enhanced command line interface"""
    parser = argparse.ArgumentParser(
        description='Enhanced Phoenix Security Multi-Scanner Import Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Enhanced Features:
  - Automatic data validation and fixing
  - Intelligent payload batching
  - Retry logic with exponential backoff
  - Comprehensive error handling
  - Pre-import validation

Examples:
  # Enhanced single file import with batching
  python phoenix_multi_scanner_enhanced.py --file scan.csv --assessment "Q4 Scan" --enable-batching
  
  # Enhanced folder processing with data fixing
  python phoenix_multi_scanner_enhanced.py --folder /scans/ --fix-data --enable-batching
  
  # Debug mode with comprehensive logging
  python phoenix_multi_scanner_enhanced.py --file scan.csv --debug --error-log errors.log
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', type=str, help='Process a single scanner file')
    input_group.add_argument('--folder', type=str, help='Process all scanner files in folder')
    
    # Scanner options - ACCEPT ANY SCANNER NAME (not limited to choices)
    parser.add_argument('--scanner', type=str, default='auto',
                       help='Scanner type - specify ANY scanner name (e.g., acunetix, trivy, grype, anchore_grype, etc.) or "auto" for auto-detection. Supports 203+ scanner types.')
    parser.add_argument('--asset-type', 
                       choices=['INFRA', 'WEB', 'CLOUD', 'CONTAINER', 'REPOSITORY', 'CODE', 'BUILD'],
                       help='Override asset type for imported assets')
    
    # Import options
    parser.add_argument('--assessment', type=str, help='Assessment name (default: auto-generated)')
    parser.add_argument('--import-type', choices=['new', 'merge', 'delta'], default='new',
                       help='Import type (default: new)')
    parser.add_argument('--anonymize', action='store_true', help='Anonymize sensitive data')
    parser.add_argument('--just-tags', action='store_true', help='Only add tags, do not import')
    parser.add_argument('--create-empty-assets', action='store_true',
                       help='Zero out vulnerability risk while keeping vulnerability data (for testing/staging)')
    parser.add_argument('--create-inventory-assets', action='store_true',
                       help='Create assets even if no vulnerabilities found (with zero risk placeholder for inventory)')
    
    # Enhanced options
    parser.add_argument('--enable-batching', action='store_true', default=True,
                       help='Enable intelligent batching for large payloads (default: enabled)')
    parser.add_argument('--disable-batching', action='store_true',
                       help='Disable batching and use single requests')
    parser.add_argument('--fix-data', action='store_true', default=True,
                       help='Automatically fix data issues (default: enabled)')
    parser.add_argument('--no-fix-data', action='store_true',
                       help='Disable automatic data fixing')
    parser.add_argument('--max-batch-size', type=int, default=500,
                       help='Maximum items per batch (default: 500)')
    parser.add_argument('--max-payload-mb', type=float, default=25.0,
                       help='Maximum payload size in MB (default: 25.0)')
    
    # Configuration options
    parser.add_argument('--config', type=str, default='config_multi_scanner.ini', 
                       help='Configuration file (default: config_multi_scanner.ini)')
    parser.add_argument('--tag-file', type=str, help='Tag configuration file')
    parser.add_argument('--verify-import', action='store_true', help='Verify import after completion')
    
    # Processing options
    parser.add_argument('--file-types', nargs='+', choices=['json', 'csv', 'xml'], 
                       default=['json', 'csv', 'xml'], help='File types to process in folder mode')
    
    # Logging options
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Logging level')
    parser.add_argument('--debug', action='store_true', 
                       help='Enable debug mode with detailed logging')
    parser.add_argument('--error-log', type=str,
                       help='File to log errors to (in addition to main log)')
    
    args = parser.parse_args()
    
    # Handle conflicting options
    if args.disable_batching:
        args.enable_batching = False
    if args.no_fix_data:
        args.fix_data = False
    
    # Setup enhanced logging
    print("🔧 Setting up logging...")
    try:
        from phoenix_import_refactored import setup_logging
        setup_logging(
            log_level=args.log_level,
            debug_mode=args.debug,
            error_log_file=args.error_log,
            tool_name="phoenix_multi_scanner_enhanced"
        )
        print("✅ Logging setup complete")
    except Exception as e:
        print(f"⚠️ Logging setup failed: {e}")
    
    try:
        # Initialize enhanced manager
        manager = EnhancedMultiScannerImportManager(args.config)
        
        # Configure batching parameters
        manager.enhanced_importer.max_batch_size = args.max_batch_size
        manager.enhanced_importer.max_payload_size_mb = args.max_payload_mb
        
        logger.info(f"🚀 Starting Enhanced Phoenix Multi-Scanner Import")
        logger.info(f"   Batching: {'enabled' if args.enable_batching else 'disabled'}")
        logger.info(f"   Data Fixing: {'enabled' if args.fix_data else 'disabled'}")
        logger.info(f"   Max Batch Size: {args.max_batch_size}")
        logger.info(f"   Max Payload: {args.max_payload_mb} MB")
        
        if args.file:
            # Process single file
            result = manager.process_scanner_file_enhanced(
                args.file,
                scanner_type=args.scanner if args.scanner != 'auto' else None,
                asset_type=args.asset_type,
                assessment_name=args.assessment,
                import_type=args.import_type,
                anonymize=args.anonymize,
                just_tags=args.just_tags,
                enable_batching=args.enable_batching,
                fix_data=args.fix_data,
                create_empty_assets=args.create_empty_assets,
                create_inventory_assets=args.create_inventory_assets
            )
            
            if result['success']:
                print(f"✅ Successfully processed {args.file}")
                print(f"   Scanner: {result['scanner_type']}")
                if not args.just_tags:
                    print(f"   Assessment: {result['assessment_name']}")
                    print(f"   Assets: {result['assets_imported']}")
                    print(f"   Vulnerabilities: {result['vulnerabilities_imported']}")
                    if result.get('batching_used'):
                        batch_info = result.get('batch_summary', {})
                        print(f"   Batches: {batch_info.get('successful_batches', 0)}/{batch_info.get('total_batches', 0)} successful")
                        print(f"   Success Rate: {batch_info.get('success_rate', 0):.1f}%")
                else:
                    print(f"   Assets tagged: {result['assets_tagged']}")
                    print(f"   Tags applied: {result['tags_applied']}")
                return 0
            else:
                print(f"❌ Failed to process {args.file}: {result.get('error', 'Unknown error')}")
                return 1
        
        elif args.folder:
            # Process folder
            result = manager.process_folder_enhanced(
                args.folder,
                file_types=args.file_types,
                scanner_type=args.scanner if args.scanner != 'auto' else None,
                asset_type=args.asset_type,
                import_type=args.import_type,
                anonymize=args.anonymize,
                just_tags=args.just_tags,
                enable_batching=args.enable_batching,
                fix_data=args.fix_data,
                create_empty_assets=args.create_empty_assets,
                create_inventory_assets=args.create_inventory_assets
            )
            
            print(f"📁 Processed folder: {args.folder}")
            print(f"   Total files: {result['total_files']}")
            print(f"   ✅ Successful: {result['successful_files']}")
            print(f"   ❌ Failed: {result['failed_files']}")
            
            return 0 if result['success'] else 1
            
    except Exception as e:
        logger.error(f"❌ Enhanced import failed: {e}")
        logger.debug(traceback.format_exc())
        return 1

if __name__ == "__main__":
    sys.exit(main())
