#!/usr/bin/env python3
"""
Terraform Security Scanner
Analyzes .tf files for security vulnerabilities and assigns risk scores.
"""

import hcl2
import re
import json
from pathlib import Path
from typing import Dict, List, Any, Tuple


def parse_terraform_file(file_path: str) -> Dict[str, Any]:
    """Parse a Terraform file and return its structure."""
    try:
        with open(file_path, 'r') as file:
            return hcl2.loads(file.read())
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return {}


def check_open_security_groups(tf_content: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for security groups with ingress from 0.0.0.0/0."""
    vulnerabilities = []
    
    if 'resource' not in tf_content:
        return vulnerabilities
    
    resources = tf_content['resource']
    if isinstance(resources, list):
        for resource_block in resources:
            for resource_type, resource_configs in resource_block.items():
                if resource_type == 'aws_security_group':
                    for name, config in resource_configs.items():
                        if 'ingress' in config:
                            ingress_rules = config['ingress']
                            if not isinstance(ingress_rules, list):
                                ingress_rules = [ingress_rules]
                            
                            for rule in ingress_rules:
                                cidr_blocks = rule.get('cidr_blocks', [])
                                if '0.0.0.0/0' in cidr_blocks:
                                    vulnerabilities.append({
                                        'severity': 'CRITICAL',
                                        'points': 30,
                                        'message': f'Open security group access from internet in {name}',
                                        'resource': f'{resource_type}.{name}'
                                    })
    
    return vulnerabilities


def check_hardcoded_secrets(tf_content: Dict[str, Any], raw_content: str = "") -> List[Dict[str, Any]]:
    """Check for hardcoded passwords and secrets."""
    vulnerabilities = []
    secret_patterns = [
        r'password\s*=\s*["\'](?!var\.)[^"\']+["\']',
        r'secret\s*=\s*["\'](?!var\.)[^"\']+["\']',
        r'api_key\s*=\s*["\'](?!var\.)[^"\']+["\']',
        r'access_key\s*=\s*["\'](?!var\.)[^"\']+["\']'
    ]
    
    search_content = raw_content if raw_content else json.dumps(tf_content)
    
    for pattern in secret_patterns:
        matches = re.finditer(pattern, search_content, re.IGNORECASE)
        for match in matches:
            vulnerabilities.append({
                'severity': 'CRITICAL',
                'points': 30,
                'message': 'Hardcoded secret detected',
                'resource': 'configuration'
            })
    
    return vulnerabilities


def check_public_s3_buckets(tf_content: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for S3 buckets with public access."""
    vulnerabilities = []
    
    if 'resource' not in tf_content:
        return vulnerabilities
    
    resources = tf_content['resource']
    if isinstance(resources, list):
        for resource_block in resources:
            for resource_type, resource_configs in resource_block.items():
                if resource_type == 'aws_s3_bucket_public_access_block':
                    for name, config in resource_configs.items():
                        if (config.get('block_public_acls', True) == False or
                            config.get('block_public_policy', True) == False or
                            config.get('ignore_public_acls', True) == False or
                            config.get('restrict_public_buckets', True) == False):
                            
                            vulnerabilities.append({
                                'severity': 'HIGH',
                                'points': 20,
                                'message': f'S3 bucket with public access enabled in {name}',
                                'resource': f'{resource_type}.{name}'
                            })
    
    return vulnerabilities


def check_unencrypted_storage(tf_content: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for RDS and EBS without encryption."""
    vulnerabilities = []
    
    if 'resource' not in tf_content:
        return vulnerabilities
    
    resources = tf_content['resource']
    if isinstance(resources, list):
        for resource_block in resources:
            for resource_type, resource_configs in resource_block.items():
                if resource_type == 'aws_db_instance':
                    for name, config in resource_configs.items():
                        if not config.get('storage_encrypted', False):
                            vulnerabilities.append({
                                'severity': 'HIGH',
                                'points': 20,
                                'message': f'Unencrypted RDS instance in {name}',
                                'resource': f'{resource_type}.{name}'
                            })
                
                elif resource_type == 'aws_ebs_volume':
                    for name, config in resource_configs.items():
                        if not config.get('encrypted', False):
                            vulnerabilities.append({
                                'severity': 'HIGH',
                                'points': 20,
                                'message': f'Unencrypted EBS volume in {name}',
                                'resource': f'{resource_type}.{name}'
                            })
    
    return vulnerabilities


def calculate_score(vulnerabilities: List[Dict[str, Any]]) -> int:
    """Calculate security risk score based on vulnerabilities."""
    total_points = sum(vuln['points'] for vuln in vulnerabilities)
    return min(total_points, 100)


def scan_terraform_file(file_path: str) -> Dict[str, Any]:
    """Main function to scan a Terraform file."""
    tf_content = parse_terraform_file(file_path)
    
    # Read raw content for secret detection
    try:
        with open(file_path, 'r') as file:
            raw_content = file.read()
    except Exception:
        raw_content = ""
    
    if not tf_content:
        return {"score": 0, "vulnerabilities": []}
    
    all_vulnerabilities = []
    
    # Run security checks
    all_vulnerabilities.extend(check_open_security_groups(tf_content))
    all_vulnerabilities.extend(check_hardcoded_secrets(tf_content, raw_content))
    all_vulnerabilities.extend(check_public_s3_buckets(tf_content))
    all_vulnerabilities.extend(check_unencrypted_storage(tf_content))
    
    score = calculate_score(all_vulnerabilities)
    
    return {
        "score": score,
        "vulnerabilities": all_vulnerabilities
    }


def format_results(results: Dict[str, Any]) -> str:
    """Format scan results for display."""
    score = results['score']
    vulnerabilities = results['vulnerabilities']
    
    critical_count = sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL')
    high_count = sum(1 for v in vulnerabilities if v['severity'] == 'HIGH')
    
    output = f"Risk Score: {score}/100\n"
    output += f"Critical: {critical_count} issues\n"
    output += f"High: {high_count} issues\n"
    output += "Details:\n\n"
    
    for vuln in vulnerabilities:
        output += f"[{vuln['severity']}] {vuln['message']}\n"
    
    return output


def main():
    """Main entry point."""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python security_scanner.py <terraform_file.tf>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not Path(file_path).exists():
        print(f"Error: File {file_path} not found")
        sys.exit(1)
    
    results = scan_terraform_file(file_path)
    print(format_results(results))


if __name__ == "__main__":
    main()