# Lab 01: Refining IAM Permissions Like A Pro

**Role:** Chief Cloud Architect  
**Focus:** Least Privilege Enforcement, IAM Policy Validation, & Finding Remediation  

---

## 📌 Lab Objective
Hands-on execution of AWS IAM policy validation to detect invalid actions (e.g., `s3:GetObjct`) and overly permissive wildcards (e.g., `s3:*`), followed by structured remediation to achieve zero security findings (`"findings": []`).

---

## 🛡️ Key Security Controls
* **Syntax & Action Validation:** Identifies typos and non-existent IAM API actions before policy deployment.
* **Wildcard Restriction:** Replaces broad resource and action wildcards (`*`) with scoped, least-privilege permissions.
* **Zero-Finding Baseline:** Verifies clean validation output (`"findings": []`) prior to production rollout.
  
