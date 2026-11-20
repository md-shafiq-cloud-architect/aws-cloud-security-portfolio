# AWS Security Reference Architecture (SRA) Compliance Engine

This module provides an automated compliance validation engine aligned with the **AWS Security Reference Architecture (SRA)** and RFC 2119 standards. It evaluates multi-account AWS environment telemetry against enterprise security guardrails.

## 📂 Repository Contents
- `sra_compliance_engine.py`: Core Python validation engine (`MasterSRAComplianceEngine`) and enterprise baseline configuration.
- `05_aws_sra_validation_lab.ipynb`: Interactive Google Colab notebook demonstrating compliance evaluation and audit reporting.

## 🛡️ Key Security Guardrails Evaluated
- **Identity & Access Management:** Enforces zero manual IAM users and mandatory IAM Identity Center (IDC) MFA.
- **Account Governance:** Validates centralized root management and delegated administrator configurations.
- **Network & Perimeter Security:** Verifies Transit Gateway connectivity, firewall subnet isolation, Multi-AZ firewall endpoints, and DNS Firewall exfiltration blocks.
- **Resource Sharing (RAM):** Audits external account sharing and prevents unauthorized organization-wide sharing.

## 🚀 Usage
Run the validation engine directly in Python or execute the interactive cells inside `05_aws_sra_validation_lab.ipynb` via Google Colab to generate a JSON compliance audit report.
