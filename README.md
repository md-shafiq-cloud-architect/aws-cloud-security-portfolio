

# 🛡️ AWS Cloud Security Architecture Portfolio

**Chief Cloud Architect:** MD Shafiqul Islam Shraban (`md-shafiq-cloud-architect`)  
**Focus Areas:** Enterprise Cloud Security, Zero Trust Architecture, IAM Governance, DevSecOps (CI/CD), Compliance Automation

---

## 📂 Completed Security Modules & Labs

### 1. [Refining IAM Permissions & Automated Policy Guardrails](./01_refining_iam_permissions.ipynb)
* **Architecture:** Event-driven security monitoring using **IAM Access Analyzer**, **EventBridge**, **AWS Lambda**, and **SNS**.
* **CI/CD Gatekeeper:** Automated static validation (`cfn-lint`) and preventative policy checks (`CheckAccessNotGranted`) inside **AWS CodeBuild** to block wildcard (`*`) and privilege escalation permissions.
* **FinOps & Alert Governance:** Implemented Archive Rules to prevent alert fatigue and configured **AWS Budgets** (80% spend threshold) with automated resource cleanup.

### 2. [Integrating IAM Access Analyzer into CI/CD Pipelines](./02_iam_access_analyzer_cicd.ipynb)
* **Secure Container Supply Chain:** Built hardened Docker images with `.dockerignore` secret filtering, **AWS ECR AES-256 Encryption**, **Tag Immutability**, and automated **CVE Vulnerability Scanning**.
* **Production Guardrails:** Enforced Git Pull Request workflows, automated `pytest` verification, and a **Manual Approval Gate** prior to **AWS Fargate** production deployment.
* ### 3. [IAM Identity Center: Empowering Secure Access to Generative AI Applications](./03-iam-identity-center-genai-security)
* **Architecture:** Centralized workforce identity governance using **AWS IAM Identity Center**, **SAML 2.0**, and **SCIM v2.0** across **Okta**, **Microsoft Entra ID**, and **Google Workspace**.
* **GenAI Access Control:** Configured console-less IDE access for **Amazon Q Developer** (90-day session lifecycle) and centralized portal access for **Amazon Q Business**.
* **Trusted Identity Propagation (TIP):** Implemented OAuth 2.0 / OIDC token exchange (`CreateTokenWithIAM` + `AssumeRole` with `ProvidedContexts`) and a 60-second pre-expiry auto-refresh timer for secure custom frontend `ChatSync` API calls.
  
