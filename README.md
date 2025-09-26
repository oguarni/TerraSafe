# TerraSafe - Terraform Security Scanner

A Python-based security scanner for Terraform Infrastructure as Code (IaC) files that identifies security vulnerabilities and assigns risk scores.

## Features

- Analyzes `.tf` files for security vulnerabilities
- Assigns risk scores from 0-100
- Detects critical and high-severity security issues
- Supports local execution (no cloud dependencies)

## Security Checks

### Critical Issues (30 points each)
- Security groups with ingress from 0.0.0.0/0 (internet-facing)
- Hardcoded passwords/secrets in configurations

### High Severity Issues (20 points each)
- S3 buckets with public access enabled
- RDS instances without encryption
- EBS volumes without encryption

## Requirements

- Python 3.8+
- Required packages: `hcl2`

## Installation

1. Install the required dependency:
```bash
pip install python-hcl2
```

## Usage

Run the scanner on a Terraform file:

```bash
python security_scanner.py <terraform_file.tf>
```

### Example Usage

```bash
# Scan a vulnerable configuration
python security_scanner.py test_files/vulnerable.tf

# Scan a secure configuration  
python security_scanner.py test_files/secure.tf
```

## Sample Output

```
Risk Score: 85/100
Critical: 2 issues
High: 1 issue
Details:

[CRITICAL] Open security group access from internet in web_sg
[CRITICAL] Hardcoded secret detected
[HIGH] Unencrypted RDS instance in main_db
```

## Test Files

- `test_files/vulnerable.tf` - Contains multiple security issues (should score 80-100)
- `test_files/secure.tf` - Follows security best practices (should score 0-20)

## Score Interpretation

- **0-20**: Low risk - Good security posture
- **21-50**: Medium risk - Some security concerns
- **51-80**: High risk - Multiple security issues
- **81-100**: Critical risk - Immediate attention required

## Implementation Details

- Maximum 200 lines of code
- Uses only: hcl2, re, json, pathlib
- Single file solution
- Functions limited to 20 lines each
- Returns structured data: `{"score": int, "vulnerabilities": list}`

## Limitations

- Only analyzes static Terraform configurations
- Does not validate actual AWS resource states
- Limited to predefined security patterns
- No support for custom rules or plugins