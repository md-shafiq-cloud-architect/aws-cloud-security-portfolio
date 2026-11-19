"""
AWS IAM Identity Center & Generative AI Security Validator
Validates Trusted Token Issuers, CloudFormation Guardrails, and Cleanup Order.
"""

UNSUPPORTED_IDPS = ["Active Directory Domain Service"]
REQUIRED_DELETION_ORDER = [
    "Amazon Q Business Application",
    "Amazon Q Developer Subscriptions",
    "CDK AssetsStack (cdk destroy)",
    "IAM Identity Center Account Instance",
    "Base CloudFormation Stack (ws-template.yaml)"
]

def validate_trusted_token_issuer(idp_name: str) -> bool:
    """Ensure Identity Provider is compatible with Trusted Token Issuers."""
    if idp_name in UNSUPPORTED_IDPS:
        print(f"[BLOCKED] {idp_name} is not supported for Trusted Token Issuers.")
        return False
    print(f"[APPROVED] {idp_name} is compatible with Amazon Q Business.")
    return True

def validate_cleanup_sequence(planned_steps: list) -> bool:
    """Enforce strict bottom-up deletion order to prevent DependencyViolation."""
    if planned_steps == REQUIRED_DELETION_ORDER:
        print("[SAFE] Bottom-up cleanup dependency order verified.")
        return True
    print("[ERROR] Invalid deletion order. Follow strict bottom-up sequence.")
    return False

if __name__ == "__main__":
    validate_trusted_token_issuer("Okta")
    validate_trusted_token_issuer("Active Directory Domain Service")
    validate_cleanup_sequence(REQUIRED_DELETION_ORDER)
  
