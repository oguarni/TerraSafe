#!/usr/bin/env python3
"""
TerraSafe - Intelligent Terraform Security Scanner
Combines rule-based detection with ML anomaly detection using Isolation Forest
"""

import re
import sys
import json
import numpy as np
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Tuple, Optional

import hcl2
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib


class Severity(Enum):
    """Security severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Vulnerability:
    """Represents a security vulnerability"""
    severity: Severity
    points: int
    message: str
    resource: str
    remediation: str = ""


class SecurityRuleEngine:
    """Rule-based security detection engine"""
    
    def __init__(self):
        self.vulnerabilities = []
    
    def check_open_security_groups(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for security groups with open access (0.0.0.0/0)"""
        vulns = []
        
        if 'resource' not in tf_content:
            return vulns
        
        for resource in tf_content.get('resource', []):
            if 'aws_security_group' in resource:
                sg_list = resource['aws_security_group']
                # Handle both list and dict formats
                if isinstance(sg_list, list):
                    sg_items = sg_list
                else:
                    sg_items = [sg_list]
                
                for sg_item in sg_items:
                    if isinstance(sg_item, dict):
                        for sg_name, sg_config in sg_item.items():
                            # Check ingress rules
                            for ingress in sg_config.get('ingress', []):
                                cidr_blocks = ingress.get('cidr_blocks', [])
                                from_port = ingress.get('from_port', 0)
                                
                                if '0.0.0.0/0' in cidr_blocks:
                                    if from_port == 22:
                                        vulns.append(Vulnerability(
                                            severity=Severity.CRITICAL,
                                            points=30,
                                            message=f"[CRITICAL] Open security group - SSH port 22 exposed to internet",
                                            resource=sg_name,
                                            remediation="Restrict SSH access to specific IP ranges"
                                        ))
                                    elif from_port == 3389:
                                        vulns.append(Vulnerability(
                                            severity=Severity.CRITICAL,
                                            points=30,
                                            message=f"[CRITICAL] Open security group - RDP port 3389 exposed to internet",
                                            resource=sg_name,
                                            remediation="Restrict RDP access to specific IP ranges"
                                        ))
                                    elif from_port == 80 or from_port == 443:
                                        vulns.append(Vulnerability(
                                            severity=Severity.MEDIUM,
                                            points=10,
                                            message=f"[MEDIUM] HTTP/HTTPS port {from_port} open to internet",
                                            resource=sg_name,
                                            remediation="Consider using a CDN or WAF for public web services"
                                        ))
                                    else:
                                        vulns.append(Vulnerability(
                                            severity=Severity.HIGH,
                                            points=20,
                                            message=f"[HIGH] Port {from_port} exposed to internet",
                                            resource=sg_name,
                                            remediation="Restrict access to specific IP ranges"
                                        ))
        
        return vulns
    
    def check_hardcoded_secrets(self, raw_content: str) -> List[Vulnerability]:
        """Check for hardcoded passwords and secrets using regex"""
        vulns = []
        
        # Pattern for hardcoded passwords (not variables)
        password_pattern = r'password\s*=\s*"([^"]+)"'
        matches = re.finditer(password_pattern, raw_content, re.IGNORECASE)
        
        for match in matches:
            password_value = match.group(1)
            # Skip if it's a variable reference
            if not password_value.startswith('var.') and not password_value.startswith('${'):
                vulns.append(Vulnerability(
                    severity=Severity.CRITICAL,
                    points=30,
                    message=f"[CRITICAL] Hardcoded password detected",
                    resource="Database/Instance",
                    remediation="Use variables or secrets manager for sensitive data"
                ))
        
        # Check for API keys and tokens
        secret_patterns = [
            (r'api_key\s*=\s*"([^"]+)"', "API key"),
            (r'secret_key\s*=\s*"([^"]+)"', "Secret key"),
            (r'token\s*=\s*"([^"]+)"', "Token")
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, raw_content, re.IGNORECASE)
            for match in matches:
                value = match.group(1)
                if not value.startswith('var.') and not value.startswith('${'):
                    vulns.append(Vulnerability(
                        severity=Severity.CRITICAL,
                        points=30,
                        message=f"[CRITICAL] Hardcoded {secret_type} detected",
                        resource="Configuration",
                        remediation="Use environment variables or secrets manager"
                    ))
        
        return vulns
    
    def check_encryption(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for unencrypted storage resources"""
        vulns = []
        
        if 'resource' not in tf_content:
            return vulns
        
        for resource in tf_content.get('resource', []):
            # Check RDS instances
            if 'aws_db_instance' in resource:
                db_list = resource['aws_db_instance']
                if isinstance(db_list, list):
                    db_items = db_list
                else:
                    db_items = [db_list]
                    
                for db_item in db_items:
                    if isinstance(db_item, dict):
                        for db_name, db_config in db_item.items():
                            if not db_config.get('storage_encrypted', False):
                                vulns.append(Vulnerability(
                                    severity=Severity.HIGH,
                                    points=20,
                                    message=f"[HIGH] Unencrypted RDS instance",
                                    resource=db_name,
                                    remediation="Enable storage_encrypted = true"
                                ))
            
            # Check EBS volumes
            if 'aws_ebs_volume' in resource:
                vol_list = resource['aws_ebs_volume']
                if isinstance(vol_list, list):
                    vol_items = vol_list
                else:
                    vol_items = [vol_list]
                    
                for vol_item in vol_items:
                    if isinstance(vol_item, dict):
                        for vol_name, vol_config in vol_item.items():
                            if not vol_config.get('encrypted', False):
                                vulns.append(Vulnerability(
                                    severity=Severity.HIGH,
                                    points=20,
                                    message=f"[HIGH] Unencrypted EBS volume",
                                    resource=vol_name,
                                    remediation="Enable encrypted = true"
                                ))
        
        return vulns
    
    def check_public_s3(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for public S3 bucket configurations"""
        vulns = []
        
        if 'resource' not in tf_content:
            return vulns
        
        for resource in tf_content.get('resource', []):
            if 'aws_s3_bucket_public_access_block' in resource:
                bucket_list = resource['aws_s3_bucket_public_access_block']
                if isinstance(bucket_list, list):
                    bucket_items = bucket_list
                else:
                    bucket_items = [bucket_list]
                    
                for bucket_item in bucket_items:
                    if isinstance(bucket_item, dict):
                        for bucket_name, config in bucket_item.items():
                            public_settings = [
                                ('block_public_acls', config.get('block_public_acls', True)),
                                ('block_public_policy', config.get('block_public_policy', True)),
                                ('ignore_public_acls', config.get('ignore_public_acls', True)),
                                ('restrict_public_buckets', config.get('restrict_public_buckets', True))
                            ]
                            
                            public_count = sum(1 for _, value in public_settings if not value)
                            
                            if public_count >= 3:
                                vulns.append(Vulnerability(
                                    severity=Severity.HIGH,
                                    points=20,
                                    message=f"[HIGH] S3 bucket with public access enabled",
                                    resource=bucket_name,
                                    remediation="Enable all public access blocks"
                                ))
                            elif public_count > 0:
                                vulns.append(Vulnerability(
                                    severity=Severity.MEDIUM,
                                    points=10,
                                    message=f"[MEDIUM] S3 bucket with partial public access",
                                    resource=bucket_name,
                                    remediation="Review and restrict public access settings"
                                ))
        
        return vulns
    
    def analyze(self, tf_content: Dict, raw_content: str) -> List[Vulnerability]:
        """Run all security checks"""
        all_vulns = []
        
        # Run all checks
        all_vulns.extend(self.check_open_security_groups(tf_content))
        all_vulns.extend(self.check_hardcoded_secrets(raw_content))
        all_vulns.extend(self.check_encryption(tf_content))
        all_vulns.extend(self.check_public_s3(tf_content))
        
        return all_vulns


class ModelManager:
    """Manages ML model persistence and loading"""
    
    def __init__(self, model_dir: str = "models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        self.model_path = self.model_dir / "isolation_forest.pkl"
        self.scaler_path = self.model_dir / "scaler.pkl"
    
    def save_model(self, model: IsolationForest, scaler: StandardScaler) -> bool:
        """Save trained model and scaler"""
        try:
            joblib.dump(model, self.model_path)
            joblib.dump(scaler, self.scaler_path)
            return True
        except Exception as e:
            print(f"Error saving model: {e}")
            return False
    
    def load_model(self) -> Tuple[Optional[IsolationForest], Optional[StandardScaler]]:
        """Load saved model and scaler"""
        try:
            if self.model_path.exists() and self.scaler_path.exists():
                model = joblib.load(self.model_path)
                scaler = joblib.load(self.scaler_path)
                return model, scaler
        except Exception as e:
            print(f"Error loading model: {e}")
        
        return None, None
    
    def model_exists(self) -> bool:
        """Check if saved model exists"""
        return self.model_path.exists() and self.scaler_path.exists()


class IntelligentSecurityScanner:
    """Main scanner combining rule-based and ML anomaly detection"""
    
    def __init__(self):
        self.rule_engine = SecurityRuleEngine()
        self.model_manager = ModelManager()
        self.model = None
        self.scaler = None
        
        # Initialize or load ML model
        self._initialize_ml_model()
    
    def _initialize_ml_model(self):
        """Initialize or load the ML model"""
        # Try to load existing model
        self.model, self.scaler = self.model_manager.load_model()
        
        if self.model is None:
            print("Training new ML model...")
            self._train_baseline_model()
    
    def _train_baseline_model(self):
        """Train ML model on baseline secure configurations"""
        # Create synthetic baseline data (secure patterns)
        baseline_features = np.array([
            # [open_ports, secrets, public_access, unencrypted, resource_count]
            [0, 0, 0, 0, 5],  # Fully secure
            [0, 0, 0, 0, 10], # Fully secure, more resources
            [1, 0, 0, 0, 8],  # One HTTP port open (acceptable)
            [0, 0, 0, 0, 15], # Fully secure, many resources
            [1, 0, 1, 0, 12], # HTTP open, partial S3 public (web app)
        ])
        
        # Add some noise for robustness
        noise = np.random.normal(0, 0.1, baseline_features.shape)
        baseline_features = baseline_features + noise
        
        # Train scaler and model
        self.scaler = StandardScaler()
        scaled_features = self.scaler.fit_transform(baseline_features)
        
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.model.fit(scaled_features)
        
        # Save model
        self.model_manager.save_model(self.model, self.scaler)
        print("ML model trained and saved")
    
    def extract_features(self, vulnerabilities: List[Vulnerability]) -> np.ndarray:
        """Extract feature vector from vulnerabilities for ML model"""
        features = {
            'open_ports': 0,
            'hardcoded_secrets': 0,
            'public_access': 0,
            'unencrypted_storage': 0,
            'total_resources': 5  # Default estimate
        }
        
        for vuln in vulnerabilities:
            if 'open security group' in vuln.message.lower() or 'exposed to internet' in vuln.message.lower():
                features['open_ports'] += 1
            elif 'hardcoded' in vuln.message.lower() or 'secret' in vuln.message.lower():
                features['hardcoded_secrets'] += 1
            elif 's3 bucket' in vuln.message.lower() and 'public' in vuln.message.lower():
                features['public_access'] += 1
            elif 'unencrypted' in vuln.message.lower():
                features['unencrypted_storage'] += 1
        
        return np.array(list(features.values())).reshape(1, -1)
    
    def calculate_ml_risk_score(self, features: np.ndarray) -> Tuple[float, str]:
        """Calculate risk score using ML model"""
        if self.model is None or self.scaler is None:
            return 0.0, "LOW"
        
        # Scale features
        scaled_features = self.scaler.transform(features)
        
        # Get anomaly score (-1 for anomaly, 1 for normal)
        prediction = self.model.predict(scaled_features)[0]
        
        # Get decision function score (distance from normal)
        anomaly_score = self.model.decision_function(scaled_features)[0]
        
        # Convert to risk score (0-100)
        # More negative = more anomalous = higher risk
        if prediction == -1:  # Anomaly detected
            risk_score = min(100, max(50, 50 + abs(anomaly_score) * 100))
        else:  # Normal pattern
            risk_score = max(0, min(50, 50 - anomaly_score * 50))
        
        # Determine confidence
        if abs(anomaly_score) > 0.3:
            confidence = "HIGH"
        elif abs(anomaly_score) > 0.1:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        return risk_score, confidence
    
    def scan(self, filepath: str) -> Dict[str, Any]:
        """Main scanning method"""
        path = Path(filepath)
        
        if not path.exists():
            return {
                'score': -1,
                'error': f'File not found: {filepath}'
            }
        
        try:
            # Read file
            with open(path, 'r') as f:
                raw_content = f.read()
            
            # Parse HCL2
            tf_content = hcl2.loads(raw_content)
            
            # Run rule-based analysis
            vulnerabilities = self.rule_engine.analyze(tf_content, raw_content)
            
            # Calculate rule-based score
            rule_score = min(100, sum(v.points for v in vulnerabilities))
            
            # Extract features for ML
            features = self.extract_features(vulnerabilities)
            
            # Calculate ML risk score
            ml_score, confidence = self.calculate_ml_risk_score(features)
            
            # Hybrid score (weighted average)
            final_score = int(0.6 * rule_score + 0.4 * ml_score)
            
            # Prepare results
            results = {
                'file': str(path),
                'score': final_score,
                'rule_based_score': rule_score,
                'ml_score': ml_score,
                'confidence': confidence,
                'vulnerabilities': [
                    {
                        'severity': v.severity.value,
                        'message': v.message,
                        'resource': v.resource,
                        'remediation': v.remediation
                    }
                    for v in vulnerabilities
                ],
                'summary': {
                    'critical': sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL),
                    'high': sum(1 for v in vulnerabilities if v.severity == Severity.HIGH),
                    'medium': sum(1 for v in vulnerabilities if v.severity == Severity.MEDIUM),
                    'low': sum(1 for v in vulnerabilities if v.severity == Severity.LOW)
                }
            }
            
            return results
            
        except Exception as e:
            return {
                'score': -1,
                'error': f'Scanning error: {type(e).__name__}: {str(e)}'
            }


def format_results(results: Dict[str, Any]) -> str:
    """Format results for console output"""
    if results['score'] == -1:
        return f"❌ Error: {results.get('error', 'Unknown error')}"
    
    output = []
    output.append("\n" + "=" * 60)
    output.append(f"🔍 TERRAFORM SECURITY SCAN RESULTS")
    output.append("=" * 60)
    output.append(f"📁 File: {results['file']}")
    output.append("-" * 60)
    
    # Risk score with color coding
    score = results['score']
    if score >= 70:
        score_color = "\033[91m"  # Red
        status = "❌ CRITICAL RISK"
    elif score >= 40:
        score_color = "\033[93m"  # Yellow
        status = "⚠️  MEDIUM RISK"
    else:
        score_color = "\033[92m"  # Green
        status = "✅ LOW RISK"
    
    output.append(f"\n{status}")
    output.append(f"{score_color}📊 Final Risk Score: {score}/100\033[0m")
    output.append(f"├─ Rule-based Score: {results['rule_based_score']}/100")
    output.append(f"├─ ML Anomaly Score: {results['ml_score']:.1f}/100")
    output.append(f"└─ Confidence: {results['confidence']}")
    
    # Summary
    summary = results['summary']
    if sum(summary.values()) > 0:
        output.append(f"\n📋 Issue Summary:")
        if summary['critical'] > 0:
            output.append(f"   \033[91m🔴 Critical: {summary['critical']}\033[0m")
        if summary['high'] > 0:
            output.append(f"   \033[93m🟠 High: {summary['high']}\033[0m")
        if summary['medium'] > 0:
            output.append(f"   \033[94m🟡 Medium: {summary['medium']}\033[0m")
        if summary['low'] > 0:
            output.append(f"   \033[96m🟢 Low: {summary['low']}\033[0m")
    
    # Vulnerabilities
    if results['vulnerabilities']:
        output.append(f"\n🚨 Detected Vulnerabilities:")
        output.append("-" * 60)
        for vuln in results['vulnerabilities']:
            output.append(f"\n{vuln['message']}")
            output.append(f"   📍 Resource: {vuln['resource']}")
            if vuln['remediation']:
                output.append(f"   💡 Fix: {vuln['remediation']}")
    else:
        output.append(f"\n\033[92m✅ No security issues detected!\033[0m")
    
    output.append("\n" + "=" * 60)
    
    return "\n".join(output)


def main():
    """Main entry point"""
    if len(sys.argv) != 2:
        print("Usage: python security_scanner.py <terraform_file.tf>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    scanner = IntelligentSecurityScanner()
    
    print(f"🔐 TerraSafe - Intelligent Terraform Security Scanner")
    print(f"🤖 Using hybrid approach: Rules + ML Anomaly Detection")
    
    results = scanner.scan(filepath)
    
    # Print formatted results
    print(format_results(results))
    
    # Save JSON results
    json_output = Path("scan_results.json")
    with open(json_output, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n📄 Detailed results saved to {json_output}")
    
    # Exit code based on risk
    if results['score'] >= 70:
        sys.exit(1)  # High risk
    sys.exit(0)


if __name__ == "__main__":
    main()