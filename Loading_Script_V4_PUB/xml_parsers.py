#!/usr/bin/env python3
"""
XML Parsers Module
==================

Dedicated XML parsers for scanner formats that require custom XML handling.
Handles Burp Suite, Checkmarx, Qualys, and other XML-based scanner outputs.
"""

import xml.etree.ElementTree as ET
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class BurpSuiteXMLParser:
    """Parser for Burp Suite XML export format"""
    
    @staticmethod
    def parse(xml_path: str) -> List[Dict[str, Any]]:
        """
        Parse Burp Suite XML file.
        Returns list of findings in standard format.
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            findings = []
            
            # Burp Suite format: <issues><issue>...</issue></issues>
            for issue in root.findall('.//issue'):
                finding = {
                    'name': issue.findtext('name', 'Unknown Issue'),
                    'host': issue.findtext('host', ''),
                    'path': issue.findtext('path', '/'),
                    'location': issue.findtext('location', ''),
                    'severity': issue.findtext('severity', 'Medium'),
                    'confidence': issue.findtext('confidence', 'Certain'),
                    'issue_background': issue.findtext('issueBackground', ''),
                    'remediation_background': issue.findtext('remediationBackground', ''),
                    'issue_detail': issue.findtext('issueDetail', ''),
                    'remediation_detail': issue.findtext('remediationDetail', ''),
                    'vulnerability_classifications': issue.findtext('vulnerabilityClassifications', ''),
                    'references': issue.findtext('references', ''),
                    'request_response': []
                }
                
                # Extract request/response pairs
                for rr in issue.findall('requestresponse'):
                    finding['request_response'].append({
                        'request': rr.findtext('request', ''),
                        'response': rr.findtext('response', ''),
                    })
                
                findings.append(finding)
            
            logger.info(f"Parsed {len(findings)} issues from Burp Suite XML")
            return findings
            
        except Exception as e:
            logger.error(f"Failed to parse Burp Suite XML {xml_path}: {e}")
            return []


class CheckmarxXMLParser:
    """Parser for Checkmarx CxSAST XML export format"""
    
    @staticmethod
    def parse(xml_path: str) -> List[Dict[str, Any]]:
        """
        Parse Checkmarx XML file.
        Returns list of findings in standard format.
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            findings = []
            
            # Checkmarx format: <CxXMLResults><Query><Result>...</Result></Query></CxXMLResults>
            for query in root.findall('.//Query'):
                query_name = query.get('name', 'Unknown Query')
                query_severity = query.get('Severity', 'Medium')
                query_language = query.get('Language', '')
                query_group = query.get('group', '')
                
                for result in query.findall('Result'):
                    finding = {
                        'name': query_name,
                        'severity': query_severity,
                        'language': query_language,
                        'group': query_group,
                        'file_name': result.get('FileName', ''),
                        'line': result.get('Line', ''),
                        'column': result.get('Column', ''),
                        'false_positive': result.get('FalsePositive', 'False'),
                        'status': result.get('Status', 'New'),
                        'remark': result.get('Remark', ''),
                        'deep_link': result.get('DeepLink', ''),
                        'path': []
                    }
                    
                    # Extract path nodes
                    path = result.find('Path')
                    if path is not None:
                        for path_node in path.findall('PathNode'):
                            node_info = {
                                'file_name': path_node.findtext('FileName', ''),
                                'line': path_node.findtext('Line', ''),
                                'column': path_node.findtext('Column', ''),
                                'node_id': path_node.findtext('NodeId', ''),
                                'name': path_node.findtext('Name', ''),
                                'type': path_node.findtext('Type', ''),
                                'length': path_node.findtext('Length', ''),
                                'snippet': path_node.findtext('Snippet/Line/Code', '')
                            }
                            finding['path'].append(node_info)
                    
                    findings.append(finding)
            
            logger.info(f"Parsed {len(findings)} results from Checkmarx XML")
            return findings
            
        except Exception as e:
            logger.error(f"Failed to parse Checkmarx XML {xml_path}: {e}")
            return []


class QualysXMLParser:
    """Parser for Qualys XML export formats"""
    
    @staticmethod
    def parse(xml_path: str) -> List[Dict[str, Any]]:
        """
        Parse Qualys XML file.
        Returns list of findings in standard format.
        Handles both WebApp and VM/VMDR formats.
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # Detect format type
            if root.tag == 'WAS_SCAN_REPORT' or 'WAS' in root.tag.upper():
                return QualysXMLParser._parse_webapp(root)
            else:
                return QualysXMLParser._parse_vm(root)
                
        except Exception as e:
            logger.error(f"Failed to parse Qualys XML {xml_path}: {e}")
            return []
    
    @staticmethod
    def _parse_webapp(root: ET.Element) -> List[Dict[str, Any]]:
        """Parse Qualys WebApp Scanning XML"""
        findings = []
        
        # Extract target URL
        target = root.find('.//TARGET')
        target_url = ''
        if target is not None:
            url_elem = target.find('URL')
            target_url = url_elem.text if url_elem is not None else 'unknown'
        
        # Extract vulnerabilities
        for vuln in root.findall('.//VULNERABILITY'):
            finding = {
                'qid': vuln.findtext('QID', ''),
                'name': vuln.findtext('TITLE', 'Unknown'),
                'url': vuln.findtext('URL', target_url),
                'param': vuln.findtext('PARAM', ''),
                'category': vuln.findtext('CATEGORY', ''),
                'group': vuln.findtext('GROUP', ''),
                'severity': vuln.findtext('SEVERITY', 'Medium'),
                'detection_id': vuln.findtext('DETECTION_ID', ''),
                'ajax': vuln.findtext('AJAX', 'false'),
                'first_time_detected': vuln.findtext('FIRST_TIME_DETECTED', ''),
                'last_time_detected': vuln.findtext('LAST_TIME_DETECTED', ''),
                'last_time_tested': vuln.findtext('LAST_TIME_TESTED', ''),
                'times_detected': vuln.findtext('TIMES_DETECTED', '0'),
                'payloads': [],
                'description': '',
                'impact': '',
                'solution': ''
            }
            
            # Extract payloads
            payloads_elem = vuln.find('PAYLOADS')
            if payloads_elem is not None:
                for payload in payloads_elem.findall('PAYLOAD'):
                    request = payload.findtext('REQUEST', '')
                    response = payload.findtext('RESPONSE', '')
                    finding['payloads'].append({'request': request, 'response': response})
            
            findings.append(finding)
        
        logger.info(f"Parsed {len(findings)} vulnerabilities from Qualys WebApp XML")
        return findings
    
    @staticmethod
    def _parse_vm(root: ET.Element) -> List[Dict[str, Any]]:
        """Parse Qualys VM/VMDR XML"""
        findings = []
        
        # Extract host information and vulnerabilities
        for host in root.findall('.//HOST'):
            ip = host.findtext('IP', 'unknown')
            tracking_method = host.findtext('TRACKING_METHOD', '')
            os = host.findtext('OS', '')
            dns = host.findtext('DNS', '')
            netbios = host.findtext('NETBIOS', '')
            
            # Extract vulnerabilities for this host
            for vuln in host.findall('.//VULN'):
                finding = {
                    'host_ip': ip,
                    'host_dns': dns,
                    'host_netbios': netbios,
                    'host_os': os,
                    'tracking_method': tracking_method,
                    'qid': vuln.findtext('QID', ''),
                    'type': vuln.findtext('TYPE', ''),
                    'severity': vuln.findtext('SEVERITY', 'Medium'),
                    'port': vuln.findtext('PORT', ''),
                    'protocol': vuln.findtext('PROTOCOL', ''),
                    'fqdn': vuln.findtext('FQDN', ''),
                    'ssl': vuln.findtext('SSL', ''),
                    'status': vuln.findtext('STATUS', ''),
                    'first_found': vuln.findtext('FIRST_FOUND_DATETIME', ''),
                    'last_found': vuln.findtext('LAST_FOUND_DATETIME', ''),
                    'times_found': vuln.findtext('TIMES_FOUND', '0'),
                    'last_test': vuln.findtext('LAST_TEST_DATETIME', ''),
                    'last_update': vuln.findtext('LAST_UPDATE_DATETIME', ''),
                    'is_ignored': vuln.findtext('IS_IGNORED', 'false'),
                    'is_disabled': vuln.findtext('IS_DISABLED', 'false'),
                    'results': vuln.findtext('RESULT', '')
                }
                
                findings.append(finding)
        
        logger.info(f"Parsed {len(findings)} vulnerabilities from Qualys VM XML")
        return findings


def parse_xml_file(file_path: str, scanner_type: str = 'auto') -> List[Dict[str, Any]]:
    """
    Parse XML file based on scanner type.
    
    Args:
        file_path: Path to XML file
        scanner_type: Scanner type ('burp', 'checkmarx', 'qualys', or 'auto')
    
    Returns:
        List of findings in standard format
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        logger.error(f"XML file not found: {file_path}")
        return []
    
    # Auto-detect scanner type from file structure
    if scanner_type == 'auto':
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check root tag to determine scanner type
            if 'issue' in root.tag.lower() or any('issue' in elem.tag.lower() for elem in root):
                scanner_type = 'burp'
            elif 'cxxml' in root.tag.lower() or 'checkmarx' in root.tag.lower():
                scanner_type = 'checkmarx'
            elif 'was_scan' in root.tag.lower() or 'qualys' in root.tag.lower() or 'vuln' in root.tag.lower():
                scanner_type = 'qualys'
            else:
                logger.warning(f"Could not auto-detect XML scanner type for {file_path}, trying all parsers")
                
        except Exception as e:
            logger.warning(f"Failed to auto-detect XML type: {e}")
    
    # Parse using appropriate parser
    if scanner_type == 'burp':
        return BurpSuiteXMLParser.parse(str(file_path))
    elif scanner_type == 'checkmarx':
        return CheckmarxXMLParser.parse(str(file_path))
    elif scanner_type == 'qualys':
        return QualysXMLParser.parse(str(file_path))
    else:
        # Try all parsers
        for parser_func in [BurpSuiteXMLParser.parse, CheckmarxXMLParser.parse, QualysXMLParser.parse]:
            findings = parser_func(str(file_path))
            if findings:
                return findings
        
        logger.error(f"No XML parser could handle file: {file_path}")
        return []

