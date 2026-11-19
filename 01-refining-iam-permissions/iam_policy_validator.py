"""
AWS IAM Policy Least-Privilege & Syntax Validator (Lab 01)
Detects invalid IAM actions (typos) and overly permissive wildcards ('*').
"""

import json

VALID_S3_ACTIONS = {"s3:GetObject", "s3:PutObject", "s3:ListBucket"}

def validate_iam_policy(policy_doc: dict) -> list:
    findings = []
    for idx, statement in enumerate(policy_doc.get("Statement", []), 1):
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
            
        for action in actions:
            if action == "*" or action.endswith(":*"):
                findings.append(f"Statement {idx}: Overly permissive wildcard action '{action}' detected.")
            elif action.startswith("s3:") and action not in VALID_S3_ACTIONS:
                findings.append(f"Statement {idx}: Invalid S3 action '{action}' (possible typo).")
                
        if statement.get("Resource") == "*":
            findings.append(f"Statement {idx}: Overly permissive wildcard resource '*' detected.")
            
    return findings

if __name__ == "__main__":
    # Sample broken policy from Lab 01
    broken_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObjct", "s3:*"], "Resource": "*"}]
    }
    print("Broken Policy Findings:", json.dumps(validate_iam_policy(broken_policy), indent=2))
    
    # Remediated least-privilege policy
    clean_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::secure-portfolio-bucket/*"}]
    }
    print("Clean Policy Findings :", json.dumps(validate_iam_policy(clean_policy), indent=2))
  
