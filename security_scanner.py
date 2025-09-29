#!/usr/bin/env python3
"""
TerraSafe - Intelligent Terraform Security Scanner
Combines rule-based detection with ML anomaly detection using Isolation Forest
Enhanced version with improved ML training and error handling
"""

import re
import sys
import json
import numpy as np
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Tuple, Optional
import logging

import hcl2
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


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
            logger.info(f"Model saved to {self.model_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def load_model(self) -> Tuple[Optional[IsolationForest], Optional[StandardScaler]]:
        """Load saved model and scaler"""
        try:
            if self.model_path.exists() and self.scaler_path.exists():
                model = joblib.load(self.model_path)
                scaler = joblib.load(self.scaler_path)
                logger.info("Model loaded successfully")
                return model, scaler
        except Exception as e:
            logger.error(f"Error loading model: {e}")
        
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
            print("Training new ML model with enhanced dataset...")
            self._train_baseline_model()
    
    def _train_baseline_model(self):
        """Train ML model with realistic and diverse baseline patterns"""
        # Create comprehensive baseline patterns representing secure configurations
        # Features: [open_ports, secrets, public_access, unencrypted, resource_count]
        
        baseline_patterns = [
            # Fully secure configurations
            [0, 0, 0, 0, 5],   # Small secure microservice
            [0, 0, 0, 0, 10],  # Medium secure application
            [0, 0, 0, 0, 15],  # Large secure infrastructure
            [0, 0, 0, 0, 25],  # Enterprise secure setup
            [0, 0, 0, 0, 3],   # Minimal secure Lambda function
            
            # Web applications (acceptable public exposure)
            [1, 0, 0, 0, 8],   # Simple web app with HTTP
            [2, 0, 0, 0, 12],  # Web app with HTTP/HTTPS
            [2, 0, 1, 0, 20],  # E-commerce with CDN (public S3)
            [1, 0, 1, 0, 15],  # Static site with S3 hosting
            [2, 0, 2, 0, 30],  # Multi-region web platform
            
            # Development environments (slightly relaxed)
            [1, 0, 0, 1, 6],   # Dev env with one unencrypted volume
            [2, 0, 0, 1, 10],  # Staging with test data
            [1, 0, 1, 1, 8],   # QA environment
            [0, 0, 0, 2, 12],  # Test cluster with temp storage
            
            # Microservices architectures
            [3, 0, 0, 0, 40],  # Service mesh with multiple endpoints
            [4, 0, 1, 0, 50],  # Kubernetes cluster with ingress
            [2, 0, 0, 0, 35],  # Docker swarm setup
            [3, 0, 2, 0, 45],  # Multi-service with CDN
            
            # Data processing systems
            [0, 0, 0, 0, 20],  # Secure data pipeline
            [1, 0, 2, 0, 25],  # Analytics platform with S3
            [0, 0, 1, 0, 18],  # ML training infrastructure
            [1, 0, 3, 0, 30],  # Data lake architecture
            
            # Hybrid cloud setups
            [2, 0, 1, 1, 28],  # Hybrid with on-prem connection
            [3, 0, 2, 1, 35],  # Multi-cloud deployment
            [1, 0, 0, 0, 22],  # Edge computing nodes
            
            # Specialized workloads
            [0, 0, 0, 0, 7],   # Secure API gateway only
            [1, 0, 0, 0, 9],   # GraphQL endpoint
            [2, 0, 1, 0, 14],  # Real-time streaming service
            [0, 0, 2, 0, 16],  # Backup and disaster recovery
            [1, 0, 1, 0, 11],  # CI/CD infrastructure
        ]
        
        baseline_features = np.array(baseline_patterns)
        
        # Advanced augmentation with realistic variations
        augmented_data = baseline_features.copy()
        
        # Add noise variations for each pattern
        for pattern in baseline_features:
            for _ in range(3):  # Create 3 variations per pattern
                # Add controlled noise
                noise = np.random.normal(0, 0.15, 5)
                
                # Apply noise with constraints
                augmented = pattern + noise
                
                # Ensure non-negative values
                augmented = np.maximum(augmented, 0)
                
                # Round discrete features
                augmented[0] = np.round(augmented[0])  # open_ports
                augmented[1] = np.round(augmented[1])  # secrets
                augmented[2] = np.round(augmented[2])  # public_access
                augmented[3] = np.round(augmented[3])  # unencrypted
                augmented[4] = np.round(augmented[4])  # resources
                
                augmented_data = np.vstack([augmented_data, augmented])
        
        # Add edge cases representing acceptable boundaries
        edge_cases = np.array([
            [5, 0, 0, 0, 60],  # Large microservices (many ports but secure)
            [0, 0, 5, 0, 40],  # Content delivery network
            [3, 0, 3, 2, 50],  # Legacy migration (transitional state)
            [0, 0, 0, 3, 25],  # Development cluster (temporary unencrypted)
            [6, 0, 2, 0, 70],  # API gateway with multiple services
        ])
        
        augmented_data = np.vstack([augmented_data, edge_cases])
        
        # Train scaler with augmented data
        self.scaler = StandardScaler()
        scaled_features = self.scaler.fit_transform(augmented_data)
        
        # Configure Isolation Forest with optimized parameters
        self.model = IsolationForest(
            contamination=0.05,  # Expect 5% anomalies in production
            random_state=42,
            n_estimators=150,    # More trees for better stability
            max_samples='auto',
            max_features=1.0,    # Use all features
            bootstrap=False,
            n_jobs=-1           # Use all CPU cores
        )
        
        # Train the model
        self.model.fit(scaled_features)
        
        # Save the trained model
        self.model_manager.save_model(self.model, self.scaler)
        
        # Log training statistics
        logger.info(f"Model trained on {len(augmented_data)} samples")
        logger.info(f"Feature ranges after scaling:")
        for i, feature_name in enumerate(['open_ports', 'secrets', 'public_access', 'unencrypted', 'resources']):
            min_val = augmented_data[:, i].min()
            max_val = augmented_data[:, i].max()
            mean_val = augmented_data[:, i].mean()
            logger.info(f"  {feature_name}: min={min_val:.1f}, max={max_val:.1f}, mean={mean_val:.1f}")
        
        print(f"✅ ML model trained successfully with {len(augmented_data)} samples")
    
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
            logger.warning("Model not available, returning default score")
            return 0.0, "LOW"
        
        try:
            # Scale features
            scaled_features = self.scaler.transform(features)
            
            # Get anomaly score (-1 for anomaly, 1 for normal)
            prediction = self.model.predict(scaled_features)[0]
            
            # Get decision function score (distance from normal)
            anomaly_score = self.model.decision_function(scaled_features)[0]
            
            # Enhanced risk score calculation
            if prediction == -1:  # Anomaly detected
                # Map anomaly score to risk (more negative = higher risk)
                risk_score = min(100, max(50, 50 + abs(anomaly_score) * 100))
            else:  # Normal pattern
                # Lower risk for normal patterns
                risk_score = max(0, min(50, 50 - anomaly_score * 50))
            
            # Determine confidence based on distance from decision boundary
            if abs(anomaly_score) > 0.3:
                confidence = "HIGH"
            elif abs(anomaly_score) > 0.1:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
            
            logger.debug(f"ML Score: {risk_score:.1f}, Confidence: {confidence}, Anomaly: {anomaly_score:.3f}")
            
            return risk_score, confidence
            
        except Exception as e:
            logger.error(f"Error in ML scoring: {e}")
            return 50.0, "LOW"  # Return neutral score on error
    
    def scan(self, filepath: str) -> Dict[str, Any]:
        """Main scanning method with enhanced error handling"""
        path = Path(filepath)
        
        if not path.exists():
            return {
                'score': -1,
                'error': f'File not found: {filepath}'
            }
        
        try:
            # Read file content
            with open(path, 'r', encoding='utf-8') as f:
                raw_content = f.read()
            
            # Try multiple parsing strategies
            tf_content = None
            parse_error = None
            
            # Strategy 1: Try HCL2 parsing
            try:
                tf_content = hcl2.loads(raw_content)
            except Exception as e:
                parse_error = f"HCL2 parse failed: {str(e)}"
                logger.debug(parse_error)
                
                # Strategy 2: Try JSON parsing (some .tf files might be JSON)
                try:
                    tf_content = json.loads(raw_content)
                    parse_error = None
                except json.JSONDecodeError:
                    pass
                
                # Strategy 3: Try to extract resource blocks manually
                if tf_content is None:
                    try:
                        # Basic regex extraction as fallback
                        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"'
                        matches = re.findall(resource_pattern, raw_content)
                        if matches:
                            tf_content = {'resource': []}
                            parse_error = "Partial parse - using fallback"
                    except Exception:
                        pass
            
            # If parsing completely failed, return error
            if tf_content is None:
                return {
                    'score': -1,
                    'error': parse_error or 'Unable to parse Terraform file'
                }
            
            # Run rule-based analysis
            vulnerabilities = self.rule_engine.analyze(tf_content, raw_content)
            
            # Calculate rule-based score
            rule_score = min(100, sum(v.points for v in vulnerabilities))
            
            # Extract features for ML
            features = self.extract_features(vulnerabilities)
            
            # Calculate ML risk score
            ml_score, confidence = self.calculate_ml_risk_score(features)
            
            # Hybrid score with weighted average
            final_score = int(0.6 * rule_score + 0.4 * ml_score)
            
            # Prepare comprehensive results
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
                },
                'features_analyzed': {
                    'open_ports': int(features[0][0]),
                    'hardcoded_secrets': int(features[0][1]),
                    'public_access': int(features[0][2]),
                    'unencrypted_storage': int(features[0][3]),
                    'total_resources': int(features[0][4])
                }
            }
            
            # Add parse warning if fallback was used
            if parse_error and "Partial" in parse_error:
                results['warning'] = parse_error
            
            return results
            
        except Exception as e:
            logger.error(f"Scanning error: {type(e).__name__}: {str(e)}")
            return {
                'score': -1,
                'error': f'Scanning error: {type(e).__name__}: {str(e)}'
            }


def format_results(results: Dict[str, Any]) -> str:
    """Format results for console output with enhanced visuals"""
    if results['score'] == -1:
        return f"❌ Error: {results.get('error', 'Unknown error')}"
    
    output = []
    output.append("\n" + "=" * 60)
    output.append(f"🔍 TERRAFORM SECURITY SCAN RESULTS")
    output.append("=" * 60)
    output.append(f"📁 File: {results['file']}")
    output.append("-" * 60)
    
    # Warning if partial parse
    if 'warning' in results:
        output.append(f"⚠️  Warning: {results['warning']}")
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
    
    # Feature analysis (if available)
    if 'features_analyzed' in results:
        output.append(f"\n🔬 Feature Analysis:")
        features = results['features_analyzed']
        output.append(f"   Open Ports: {features['open_ports']}")
        output.append(f"   Hardcoded Secrets: {features['hardcoded_secrets']}")
        output.append(f"   Public Access: {features['public_access']}")
        output.append(f"   Unencrypted Storage: {features['unencrypted_storage']}")
    
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
        output.append("✓ All resources properly configured")
        output.append("✓ Encryption enabled where required")
        output.append("✓ Network access properly restricted")
    
    output.append("\n" + "=" * 60)
    
    return "\n".join(output)


def main():
    """Main entry point"""
    if len(sys.argv) != 2:
        print("Usage: python security_scanner.py <terraform_file.tf>")
        print("\nExample:")
        print("  python security_scanner.py test_files/vulnerable.tf")
        sys.exit(1)
    
    filepath = sys.argv[1]
    scanner = IntelligentSecurityScanner()
    
    print(f"🔐 TerraSafe - Intelligent Terraform Security Scanner")
    print(f"🤖 Using hybrid approach: Rules (60%) + ML Anomaly Detection (40%)")
    
    results = scanner.scan(filepath)
    
    # Print formatted results
    print(format_results(results))
    
    # Save JSON results
    json_output = Path("scan_results.json")
    with open(json_output, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n📄 Detailed results saved to {json_output}")
    
    # Exit code based on risk
    if results['score'] == -1:
        sys.exit(2)  # Error
    elif results['score'] >= 70:
        sys.exit(1)  # High risk
    sys.exit(0)  # Acceptable risk


if __name__ == "__main__":
    main()