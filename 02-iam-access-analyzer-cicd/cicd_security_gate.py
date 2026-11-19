"""
AWS DevSecOps CI/CD Security Gatekeeper (Lab 02)
Validates container image hygiene and IAM Access Analyzer policy compliance prior to ECS Fargate deployment.
"""

def evaluate_cicd_security_gate(has_dockerignore: bool, ecr_cve_count: int, analyzer_findings: list, manual_approval: bool) -> bool:
    print("=== DEVSECOPS CI/CD PIPELINE SECURITY GATE ===")
    
    if not has_dockerignore:
        print("[BLOCKED] Missing .dockerignore secret filtering.")
        return False
    if ecr_cve_count > 0:
        print(f"[BLOCKED] Amazon ECR scan detected {ecr_cve_count} critical/high vulnerabilities.")
        return False
    if len(analyzer_findings) > 0:
        print(f"[BLOCKED] IAM Access Analyzer reported findings: {analyzer_findings}")
        return False
    if not manual_approval:
        print("[PENDING] Awaiting human-in-the-loop Manual Approval Gate.")
        return False
        
    print("[APPROVED] All DevSecOps guardrails passed! Authorized for ECS Fargate production rollout.")
    return True

if __name__ == "__main__":
    # Simulate passing CI/CD security pipeline
    evaluate_cicd_security_gate(
        has_dockerignore=True,
        ecr_cve_count=0,
        analyzer_findings=[],
        manual_approval=True
    )
  
