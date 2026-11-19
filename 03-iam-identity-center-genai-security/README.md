# IAM Identity Center: Empowering Secure Access to Generative AI Applications

**Role:** Chief Cloud Architect  
**Focus:** Workforce Identity Federation, Trusted Identity Propagation (TIP), & GenAI Governance  
**AWS Level:** 300 (Advanced Cloud Security)  

---

## 📌 Project Overview

This project demonstrates an enterprise-grade security architecture for governing workforce access to Generative AI applications—specifically **Amazon Q Developer** and **Amazon Q Business**—using **AWS IAM Identity Center**. Instead of managing fragmented IAM federation or hardcoded credentials, this architecture centralizes user authentication, automates lifecycle provisioning, and propagates user identity context end-to-end from a custom frontend application to AWS APIs.

---

## 🏗️ Security Architecture & Core Components

* **Centralized Workforce Federation:** Integrates external Identity Providers (**Okta**, **Microsoft Entra ID**, **Google Workspace**) via **SAML 2.0** for Single Sign-On (SSO) and **SCIM v2.0** for automated user and group (`Qusers`) lifecycle synchronization.
* **Console-Less Developer Access (Amazon Q Developer):** Grants IDE-level access inside VS Code Server via Pro license subscriptions and 8-digit device authorization without exposing the AWS Management Console, enforcing a 90-day session lifecycle.
* **Enterprise GenAI Portal (Amazon Q Business):** Deploys an AWS Managed Application accessible through the centralized **AWS Access Portal**, ensuring per-user subscription tracking and data isolation.
* **Trusted Identity Propagation (TIP):** Implements **OAuth 2.0 / OIDC** token exchange using a **Trusted Token Issuer**, **Customer Managed Application**, **Bootstrap Role**, and **AWS STS (`AssumeRole` with `ProvidedContexts`)** to invoke the `ChatSync` API securely from a custom AngularJS web frontend.

---

## 🛡️ Key Security Controls & Architectural Trade-Offs

| Security Domain | Implementation & Best Practice | Architectural Constraint / Trade-Off |
| :--- | :--- | :--- |
| **Instance Scope** | **Organization Instance** for multi-account production governance and unified billing. | **Account Instance** is used for single-account sandboxes/PoCs only. |
| **Token Issuer Support** | Supports OIDC-compliant IdPs (Cognito, Okta, Entra ID, Auth0). | **Active Directory Domain Service** is unsupported for Trusted Token Issuers. |
| **SCIM Group Sync** | Automated CRUD sync via SCIM Endpoint & Bearer Token (Near Real-Time). | Free tiers of Entra ID & Google Workspace restrict group sync; requires CLI fallback (`aws identitystore create-group`). |
| **Token Exchange Security** | One-time `CreateTokenWithIAM` exchange with a **60-second pre-expiry auto-refresh timer**. | Prevents credential caching and enforces mutual consent between Bootstrap Role and Customer Managed App. |
| **MFA Enforcement** | **Always-On MFA** enforced in production environments. | Disabled (`Never`) strictly in isolated lab sandboxes to streamline API-created user testing. |

---

## 🧪 Automated Policy & Architecture Validation (`Python`)

To enforce security hygiene before and after deployment, this repository includes an interactive validation suite (`iam_identity_center_genai_security_validation.ipynb`) covering:

1. **Identity Center & Credential Check:** Verifies active SSO instances and `boto3` connectivity.
2. **Trusted Token Issuer Compatibility:** Blocks unsupported directory services (e.g., AD DS) while approving OIDC-compliant IdPs.
3. **CloudFormation Pre-Deployment Guardrails:** Enforces sandbox isolation, region locking (`us-east-1`), and `CAPABILITY_NAMED_IAM` acknowledgment.
4. **SAML/SCIM Federation Audit:** Evaluates user/group sync capabilities across native and third-party IdPs.
5. **6-Point Diagnostic Simulator (`diag_tool`):** Validates `.well-known/openid-configuration`, `aud` claims, principal authorization, and attribute mappings prior to frontend launch.
6. **Bottom-Up Cleanup Validator:** Enforces strict deletion dependency order (`Q Business` -> `Q Developer` -> `CDK AssetsStack` -> `Identity Center` -> `Base CloudFormation Stack`) to prevent `DependencyViolation` errors and orphaned billing.

---


