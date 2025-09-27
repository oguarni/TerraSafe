#!/usr/bin/env python3
"""
Unit tests for TerraSafe Security Scanner
Run with: pytest test_security_scanner.py -v
"""

import unittest
import tempfile
import numpy as np
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Import the scanner components
from security_scanner import (
    IntelligentSecurityScanner,
    SecurityRuleEngine,
    ModelManager,
    Vulnerability,
    Severity
)

class TestSecurityRuleEngine(unittest.TestCase):
    """Test the rule-based detection engine"""
    
    def setUp(self):
        self.engine = SecurityRuleEngine()
    
    def test_detect_open_ssh_port(self):
        """Test detection of open SSH port to internet"""
        tf_content = {
            'resource': [{
                'aws_security_group': [{
                    'test_sg': {
                        'ingress': [{
                            'from_port': 22,
                            'to_port': 22,
                            'protocol': 'tcp',
                            'cidr_blocks': ['0.0.0.0/0']
                        }]
                    }
                }]
            }]
        }
        
        vulnerabilities = self.engine.check_open_security_groups(tf_content)
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].severity, Severity.CRITICAL)
        self.assertIn('SSH', vulnerabilities[0].message.upper())
    
    def test_detect_hardcoded_password(self):
        """Test detection of hardcoded passwords"""
        raw_content = '''
        resource "aws_db_instance" "test" {
            password = "hardcoded123"
        }
        '''
        
        vulnerabilities = self.engine.check_hardcoded_secrets(raw_content)
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].severity, Severity.CRITICAL)
        self.assertIn('password', vulnerabilities[0].message.lower())
    
    def test_ignore_variable_passwords(self):
        """Test that variable references are not flagged"""
        raw_content = '''
        resource "aws_db_instance" "test" {
            password = var.db_password
        }
        '''
        
        vulnerabilities = self.engine.check_hardcoded_secrets(raw_content)
        
        self.assertEqual(len(vulnerabilities), 0)
    
    def test_detect_unencrypted_rds(self):
        """Test detection of unencrypted RDS instances"""
        tf_content = {
            'resource': [{
                'aws_db_instance': [{
                    'test_db': {
                        'storage_encrypted': False
                    }
                }]
            }]
        }
        
        vulnerabilities = self.engine.check_encryption(tf_content)
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].severity, Severity.HIGH)
        self.assertIn('RDS', vulnerabilities[0].message)
    
    def test_detect_public_s3_bucket(self):
        """Test detection of public S3 buckets"""
        tf_content = {
            'resource': [{
                'aws_s3_bucket_public_access_block': [{
                    'test_bucket': {
                        'block_public_acls': False,
                        'block_public_policy': False,
                        'ignore_public_acls': False,
                        'restrict_public_buckets': False
                    }
                }]
            }]
        }
        
        vulnerabilities = self.engine.check_public_s3(tf_content)
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].severity, Severity.HIGH)
        self.assertIn('S3', vulnerabilities[0].message)

class TestModelManager(unittest.TestCase):
    """Test ML model persistence"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = ModelManager(self.temp_dir)
    
    def tearDown(self):
        # Clean up temp directory
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_save_and_load_model(self):
        """Test saving and loading ML model"""
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        
        # Create dummy model and scaler
        model = IsolationForest(random_state=42)
        scaler = StandardScaler()
        
        # Fit with dummy data
        X = np.array([[1, 2], [3, 4], [5, 6]])
        scaler.fit(X)
        model.fit(scaler.transform(X))
        
        # Save
        success = self.manager.save_model(model, scaler)
        self.assertTrue(success)
        
        # Load
        loaded_model, loaded_scaler = self.manager.load_model()
        self.assertIsNotNone(loaded_model)
        self.assertIsNotNone(loaded_scaler)
        
        # Test that loaded model works
        test_data = np.array([[2, 3]])
        original_pred = model.predict(scaler.transform(test_data))
        loaded_pred = loaded_model.predict(loaded_scaler.transform(test_data))
        np.testing.assert_array_equal(original_pred, loaded_pred)

class TestIntelligentSecurityScanner(unittest.TestCase):
    """Test the main scanner integration"""
    
    def setUp(self):
        self.scanner = IntelligentSecurityScanner()
    
    def test_feature_extraction(self):
        """Test feature extraction from vulnerabilities"""
        vulnerabilities = [
            Vulnerability(Severity.CRITICAL, 30, "Open security group", "sg1"),
            Vulnerability(Severity.CRITICAL, 30, "Hardcoded password", "db1"),
            Vulnerability(Severity.HIGH, 20, "Unencrypted storage", "ebs1"),
        ]
        
        features = self.scanner.extract_features(vulnerabilities)
        
        self.assertEqual(features.shape, (1, 5))
        # Check feature counts: [open_ports, secrets, public_access, encrypted, resources]
        self.assertEqual(features[0][0], 1)  # 1 open port
        self.assertEqual(features[0][1], 1)  # 1 hardcoded secret
        self.assertEqual(features[0][3], 1)  # 1 unencrypted storage
    
    def test_ml_risk_scoring(self):
        """Test ML risk score calculation"""
        # Test with known risky pattern
        risky_features = np.array([[3, 2, 2, 3, 20]]).reshape(1, -1)
        risk_score, confidence = self.scanner.calculate_ml_risk_score(risky_features)
        
        self.assertIsInstance(risk_score, float)
        self.assertGreaterEqual(risk_score, 0)
        self.assertLessEqual(risk_score, 100)
        self.assertIn(confidence, ["HIGH", "MEDIUM", "LOW"])
    
    @patch('security_scanner.Path.exists')
    @patch('builtins.open')
    def test_scan_vulnerable_file(self, mock_open, mock_exists):
        """Test scanning a vulnerable configuration"""
        mock_exists.return_value = True
        
        vulnerable_content = '''
        resource "aws_security_group" "test" {
            ingress {
                from_port = 22
                to_port = 22
                protocol = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
            }
        }
        
        resource "aws_db_instance" "test" {
            password = "hardcoded123"
            storage_encrypted = false
        }
        '''
        
        mock_open.return_value.__enter__.return_value.read.return_value = vulnerable_content
        
        results = self.scanner.scan("test.tf")
        
        self.assertIn('score', results)
        self.assertIn('vulnerabilities', results)
        self.assertGreater(results['score'], 50)  # Should be high risk
        self.assertGreater(len(results['vulnerabilities']), 0)
    
    def test_scan_error_handling(self):
        """Test error handling in scan method"""
        results = self.scanner.scan("non_existent_file.tf")
        
        self.assertEqual(results['score'], -1)
        self.assertIn('error', results)

class TestVulnerabilityDataclass(unittest.TestCase):
    """Test the Vulnerability dataclass"""
    
    def test_vulnerability_creation(self):
        """Test creating vulnerability objects"""
        vuln = Vulnerability(
            severity=Severity.CRITICAL,
            points=30,
            message="Test vulnerability",
            resource="test_resource",
            remediation="Fix this way"
        )
        
        self.assertEqual(vuln.severity, Severity.CRITICAL)
        self.assertEqual(vuln.points, 30)
        self.assertEqual(vuln.message, "Test vulnerability")
        self.assertEqual(vuln.resource, "test_resource")
        self.assertEqual(vuln.remediation, "Fix this way")
    
    def test_severity_enum(self):
        """Test severity enum values"""
        self.assertEqual(Severity.CRITICAL.value, "CRITICAL")
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.LOW.value, "LOW")

if __name__ == '__main__':
    unittest.main()