#!/usr/bin/env python3
"""
Terraform Security Scanner
Analyzes .tf files for security vulnerabilities and assigns risk scores.
"""

import hcl2
import re
import json
from pathlib import Path
from typing import Dict, List, Any


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
    
    # Handle both list and dict structure
    resources = tf_content['resource']
    if not isinstance(resources, list):
        resources = [resources]
    
    for resource_block in resources:
        if 'aws_security_group' in resource_block:
            sg_resources = resource_block['aws_security_group']
            # Handle both single and multiple resources
            if not isinstance(sg_resources, list):
                sg_resources = [sg_resources]
            
            for sg in sg_resources:
                if isinstance(sg, dict):
                    for name, config in sg.items():
                        if 'ingress' in config:
                            ingress_rules = config['ingress']
                            if not isinstance(ingress_rules, list):
                                ingress_rules = [ingress_rules]
                            
                            for rule in ingress_rules:
                                cidr_blocks = rule.get('cidr_blocks', [])
                                if '0.0.0.0/0' in cidr_blocks:
                                    port = rule.get('from_port', 'any')
                                    vulnerabilities.append({
                                        'severity': 'CRITICAL',
                                        'points': 30,
                                        'message': f'Open security group - port {port} exposed to internet in {name}',
                                        'resource': f'aws_security_group.{name}'
                                    })
    
    return vulnerabilities


def check_hardcoded_secrets(tf_content: Dict[str, Any], raw_content: str = "") -> List[Dict[str, Any]]:
    """Check for hardcoded passwords and secrets."""
    vulnerabilities = []
    secret_patterns = [
        (r'password\s*=\s*"[^"$]+(?<!var\.)[^"]*"', 'password'),
        (r'secret\s*=\s*"[^"$]+(?<!var\.)[^"]*"', 'secret'),
        (r'api_key\s*=\s*"[^"$]+(?<!var\.)[^"]*"', 'API key'),
        (r'access_key\s*=\s*"[^"$]+(?<!var\.)[^"]*"', 'access key')
    ]
    
    search_content = raw_content if raw_content else json.dumps(tf_content)
    
    for pattern, secret_type in secret_patterns:
        matches = re.finditer(pattern, search_content, re.IGNORECASE)
        for match in matches:
            # Skip if it contains 'var.'
            if 'var.' not in match.group():
                vulnerabilities.append({
                    'severity': 'CRITICAL',
                    'points': 30,
                    'message': f'Hardcoded {secret_type} detected',
                    'resource': 'configuration'
                })
                break  # Count only once per pattern type
    
    return vulnerabilities


def check_public_s3_buckets(tf_content: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for S3 buckets with public access."""
    vulnerabilities = []
    
    if 'resource' not in tf_content:
        return vulnerabilities
    
    resources = tf_content['resource']
    if not isinstance(resources, list):
        resources = [resources]
    
    for resource_block in resources:
        if 'aws_s3_bucket_public_access_block' in resource_block:
            pab_resources = resource_block['aws_s3_bucket_public_access_block']
            if not isinstance(pab_resources, list):
                pab_resources = [pab_resources]
            
            for pab in pab_resources:
                if isinstance(pab, dict):
                    for name, config in pab.items():
                        # Check if any public access is allowed
                        if (not config.get('block_public_acls', True) or
                            not config.get('block_public_policy', True) or
                            not config.get('ignore_public_acls', True) or
                            not config.get('restrict_public_buckets', True)):
                            
                            vulnerabilities.append({
                                'severity': 'HIGH',
                                'points': 20,
                                'message': f'S3 bucket with public access enabled in {name}',
                                'resource': f'aws_s3_bucket_public_access_block.{name}'
                            })
    
    return vulnerabilities


def check_unencrypted_storage(tf_content: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for RDS and EBS without encryption."""
    vulnerabilities = []
    
    if 'resource' not in tf_content:
        return vulnerabilities
    
    resources = tf_content['resource']
    if not isinstance(resources, list):
        resources = [resources]
    
    for resource_block in resources:
        # Check RDS instances
        if 'aws_db_instance' in resource_block:
            db_resources = resource_block['aws_db_instance']
            if not isinstance(db_resources, list):
                db_resources = [db_resources]
            
            for db in db_resources:
                if isinstance(db, dict):
                    for name, config in db.items():
                        if not config.get('storage_encrypted', False):
                            vulnerabilities.append({
                                'severity': 'HIGH',
                                'points': 20,
                                'message': f'Unencrypted RDS instance in {name}',
                                'resource': f'aws_db_instance.{name}'
                            })
        
        # Check EBS volumes
        if 'aws_ebs_volume' in resource_block:
            ebs_resources = resource_block['aws_ebs_volume']
            if not isinstance(ebs_resources, list):
                ebs_resources = [ebs_resources]
            
            for ebs in ebs_resources:
                if isinstance(ebs, dict):
                    for name, config in ebs.items():
                        if not config.get('encrypted', False):
                            vulnerabilities.append({
                                'severity': 'HIGH',
                                'points': 20,
                                'message': f'Unencrypted EBS volume in {name}',
                                'resource': f'aws_ebs_volume.{name}'
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
    
    # Color codes for terminal output
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'
    
    # Determine color based on score
    if score >= 80:
        score_color = RED
    elif score >= 50:
        score_color = YELLOW
    else:
        score_color = GREEN
    
    output = f"\n{score_color}Risk Score: {score}/100{RESET}\n"
    output += f"{RED}Critical: {critical_count} issues{RESET}\n"
    output += f"{YELLOW}High: {high_count} issues{RESET}\n"
    
    if vulnerabilities:
        output += "\nDetails:\n"
        output += "-" * 50 + "\n"
        for vuln in vulnerabilities:
            color = RED if vuln['severity'] == 'CRITICAL' else YELLOW
            output += f"{color}[{vuln['severity']}]{RESET} {vuln['message']}\n"
    else:
        output += f"\n{GREEN}✓ No security issues found!{RESET}\n"
    
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
    
    print("\n🔍 Scanning Terraform file for security vulnerabilities...")
    results = scan_terraform_file(file_path)
    print(format_results(results))


if __name__ == "__main__":
    main()