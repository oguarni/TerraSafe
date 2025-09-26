#!/usr/bin/env python3
"""
TerraSafe - Intelligent Terraform Security Scanner
Combines rule-based detection with ML-based risk scoring
"""

import hcl2
import re
import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

class IntelligentSecurityScanner:
    """Main scanner class following Clean Architecture principles"""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize or load the anomaly detection model"""
        model_path = "models/security_model.pkl"
        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load("models/scaler.pkl")
        else:
            # Train with baseline security patterns
            self.model = IsolationForest(contamination=0.3, random_state=42)
            self._train_baseline_model()
    
    def _train_baseline_model(self):
        """Train model with known security patterns"""
        # Feature vectors: [open_ports, hardcoded_secrets, public_access, unencrypted_storage, resource_count]
        baseline_data = np.array([
            [0, 0, 0, 0, 5],  # Secure config
            [0, 0, 0, 1, 8],  # Minor issues
            [1, 0, 1, 1, 10], # Medium risk
            [2, 1, 1, 2, 15], # High risk
            [3, 2, 2, 3, 20], # Critical risk
        ])
        
        self.scaler.fit(baseline_data)
        scaled_data = self.scaler.transform(baseline_data)
        self.model.fit(scaled_data)
        
        # Save model for future use
        os.makedirs("models", exist_ok=True)
        joblib.dump(self.model, "models/security_model.pkl")
        joblib.dump(self.scaler, "models/scaler.pkl")
    
    def extract_features(self, tf_content: Dict, vulnerabilities: List) -> np.ndarray:
        """Extract feature vector from Terraform configuration"""
        features = {
            'open_ports': 0,
            'hardcoded_secrets': 0,
            'public_access': 0,
            'unencrypted_storage': 0,
            'resource_count': 0
        }
        
        # Count vulnerabilities by type
        for vuln in vulnerabilities:
            if 'Open security group' in vuln['message']:
                features['open_ports'] += 1
            elif 'Hardcoded' in vuln['message']:
                features['hardcoded_secrets'] += 1
            elif 'public access' in vuln['message']:
                features['public_access'] += 1
            elif 'Unencrypted' in vuln['message']:
                features['unencrypted_storage'] += 1
        
        # Count total resources
        if 'resource' in tf_content:
            resources = tf_content['resource']
            if isinstance(resources, list):
                features['resource_count'] = len(resources)
            else:
                features['resource_count'] = 1
        
        return np.array(list(features.values())).reshape(1, -1)
    
    def calculate_ml_risk_score(self, features: np.ndarray) -> Tuple[float, str]:
        """Use ML model to calculate risk score and confidence"""
        scaled_features = self.scaler.transform(features)
        
        # Anomaly score (-1 for anomaly, 1 for normal)
        prediction = self.model.predict(scaled_features)[0]
        
        # Decision function gives distance to separating hyperplane
        anomaly_score = self.model.decision_function(scaled_features)[0]
        
        # Convert to risk score (0-100)
        # More negative = more anomalous = higher risk
        risk_score = max(0, min(100, 50 - anomaly_score * 100))
        
        # Determine confidence based on distance from decision boundary
        confidence = "HIGH" if abs(anomaly_score) > 0.3 else "MEDIUM" if abs(anomaly_score) > 0.1 else "LOW"
        
        return risk_score, confidence
    
    def scan(self, file_path: str) -> Dict[str, Any]:
        """Main scanning method combining rule-based and ML approaches"""
        # Parse Terraform file
        tf_content = self._parse_file(file_path)
        
        # Rule-based detection
        vulnerabilities = self._detect_vulnerabilities(tf_content, file_path)
        
        # Extract features for ML
        features = self.extract_features(tf_content, vulnerabilities)
        
        # ML-based risk assessment
        ml_score, confidence = self.calculate_ml_risk_score(features)
        
        # Combine rule-based and ML scores
        rule_score = min(sum(v['points'] for v in vulnerabilities), 100)
        final_score = int(0.6 * rule_score + 0.4 * ml_score)  # Weighted average
        
        return {
            "score": final_score,
            "rule_based_score": rule_score,
            "ml_score": ml_score,
            "confidence": confidence,
            "vulnerabilities": vulnerabilities,
            "features": features.tolist()[0]
        }
    
    def _parse_file(self, file_path: str) -> Dict:
        """Parse Terraform file"""
        try:
            with open(file_path, 'r') as file:
                return hcl2.loads(file.read())
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return {}
    
    def _detect_vulnerabilities(self, tf_content: Dict, file_path: str) -> List[Dict]:
        """Run all vulnerability detection rules"""
        vulnerabilities = []
        
        # Read raw content for secret detection
        with open(file_path, 'r') as file:
            raw_content = file.read()
        
        # Run all checks
        vulnerabilities.extend(self._check_open_security_groups(tf_content))
        vulnerabilities.extend(self._check_hardcoded_secrets(raw_content))
        vulnerabilities.extend(self._check_public_s3(tf_content))
        vulnerabilities.extend(self._check_unencrypted_storage(tf_content))
        
        return vulnerabilities
    
    def _check_open_security_groups(self, tf_content: Dict) -> List[Dict]:
        """Check for open security groups"""
        vulnerabilities = []
        
        if 'resource' not in tf_content:
            return vulnerabilities
        
        resources = tf_content['resource']
        if not isinstance(resources, list):
            resources = [resources]
        
        for resource_block in resources:
            if 'aws_security_group' in resource_block:
                sg_resources = resource_block['aws_security_group']
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
                                            'message': f'Open security group - port {port} exposed to internet',
                                            'resource': f'aws_security_group.{name}'
                                        })
        
        return vulnerabilities
    
    def _check_hardcoded_secrets(self, raw_content: str) -> List[Dict]:
        """Check for hardcoded credentials"""
        vulnerabilities = []
        patterns = [
            (r'password\s*=\s*"(?!.*var\.)[^"]+hardcoded[^"]*"', 'password'),
            (r'secret\s*=\s*"(?!.*var\.)[^"]+[^"]*"', 'secret'),
        ]
        
        for pattern, secret_type in patterns:
            if re.search(pattern, raw_content, re.IGNORECASE):
                vulnerabilities.append({
                    'severity': 'CRITICAL',
                    'points': 30,
                    'message': f'Hardcoded {secret_type} detected',
                    'resource': 'configuration'
                })
                break
        
        return vulnerabilities
    
    def _check_public_s3(self, tf_content: Dict) -> List[Dict]:
        """Check for public S3 buckets"""
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
                            if not all([
                                config.get('block_public_acls', True),
                                config.get('block_public_policy', True),
                                config.get('ignore_public_acls', True),
                                config.get('restrict_public_buckets', True)
                            ]):
                                vulnerabilities.append({
                                    'severity': 'HIGH',
                                    'points': 20,
                                    'message': f'S3 bucket with public access enabled',
                                    'resource': f'aws_s3_bucket_public_access_block.{name}'
                                })
        
        return vulnerabilities
    
    def _check_unencrypted_storage(self, tf_content: Dict) -> List[Dict]:
        """Check for unencrypted storage"""
        vulnerabilities = []
        
        if 'resource' not in tf_content:
            return vulnerabilities
        
        resources = tf_content['resource']
        if not isinstance(resources, list):
            resources = [resources]
        
        for resource_block in resources:
            # Check RDS
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
                                    'message': f'Unencrypted RDS instance',
                                    'resource': f'aws_db_instance.{name}'
                                })
            
            # Check EBS
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
                                    'message': f'Unencrypted EBS volume',
                                    'resource': f'aws_ebs_volume.{name}'
                                })
        
        return vulnerabilities


def format_results(results: Dict[str, Any]) -> str:
    """Format results for display"""
    score = results['score']
    ml_score = results['ml_score']
    rule_score = results['rule_based_score']
    confidence = results['confidence']
    vulnerabilities = results['vulnerabilities']
    
    critical = sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL')
    high = sum(1 for v in vulnerabilities if v['severity'] == 'HIGH')
    
    # Color codes
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    
    score_color = RED if score >= 80 else YELLOW if score >= 50 else GREEN
    
    output = f"\n{BLUE}╔══════════════════════════════════════════╗{RESET}\n"
    output += f"{BLUE}║     INTELLIGENT SECURITY ANALYSIS        ║{RESET}\n"
    output += f"{BLUE}╚══════════════════════════════════════════╝{RESET}\n\n"
    
    output += f"{score_color}Final Risk Score: {score}/100{RESET}\n"
    output += f"├─ Rule-based Score: {rule_score}/100\n"
    output += f"├─ ML Anomaly Score: {ml_score:.1f}/100\n"
    output += f"└─ Confidence: {confidence}\n\n"
    
    output += f"{RED}Critical Issues: {critical}{RESET}\n"
    output += f"{YELLOW}High Issues: {high}{RESET}\n"
    
    if vulnerabilities:
        output += "\n📋 Detected Vulnerabilities:\n"
        output += "─" * 40 + "\n"
        for vuln in vulnerabilities:
            color = RED if vuln['severity'] == 'CRITICAL' else YELLOW
            output += f"{color}[{vuln['severity']}]{RESET} {vuln['message']}\n"
    else:
        output += f"\n{GREEN}✓ No security issues detected!{RESET}\n"
    
    output += f"\n{BLUE}Feature Vector: {results['features']}{RESET}\n"
    
    return output


def main():
    """Main entry point"""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python ml_security_scanner.py <terraform_file.tf>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not Path(file_path).exists():
        print(f"Error: File {file_path} not found")
        sys.exit(1)
    
    print("\n🤖 Initializing Intelligent Security Scanner...")
    scanner = IntelligentSecurityScanner()
    
    print("🔍 Analyzing Terraform configuration...")
    results = scanner.scan(file_path)
    
    print(format_results(results))


if __name__ == "__main__":
    main()