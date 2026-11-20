"""
Enterprise AWS Security Reference Architecture (AWS SRA) Policy-as-Code Compliance Engine.
Author: MD Shafiqul Islam Shraban (Principal Multi-Cloud Security Architect)
Covers: Multi-Account Governance, Network/RAM, Zero Trust Edge/Lattice, Compute/Nitro/Crypto,
        Multi-Region Decision & Prerequisites, and 6-Phase Implementation Guardrails.
"""

import json
import unittest
from typing import Callable, Dict, List

RULE_REGISTRY: List[Dict[str, object]] = []


def sra_rule(rule_id: str, domain: str, severity: str = "CRITICAL"):
    """Registers an architectural guardrail into the Master AWS SRA Orchestrator."""
    def decorator(func: Callable[[Dict[str, object]], bool]):
        RULE_REGISTRY.append({
            "id": rule_id,
            "domain": domain,
            "severity": severity,
            "check": func,
        })
        return func
    return decorator


# ==============================================================================
# DOMAIN 1: MULTI-ACCOUNT LANDING ZONE, IAM & CENTRAL GOVERNANCE
# ==============================================================================
@sra_rule("SRA-IAM-001", "Identity_Governance")
def check_zero_long_term_iam_users(env: Dict[str, object]) -> bool:
    return env["manual_iam_users_count"] == 0 and env["centralized_root_management_active"]


@sra_rule("SRA-IAM-002", "Identity_Governance")
def check_idc_ad_colocation_and_mfa(env: Dict[str, object]) -> bool:
    return (
        env["idc_delegated_admin_account"] == env["managed_ad_account"]
        and env["idc_mfa_enforced"]
    )


@sra_rule("SRA-IAM-003", "Identity_Governance")
def check_iam_policy_matrix_and_no_wildcards(env: Dict[str, object]) -> bool:
    return not env["uses_wildcard_resource_arn"] and env["automated_policy_exception_workflow"]


@sra_rule("SRA-APP-001", "Workload_Isolation")
def check_single_application_per_account(env: Dict[str, object]) -> bool:
    return env["apps_per_account"] == 1 and not env["shares_roles_or_datastores"]


# ==============================================================================
# DOMAIN 2: NETWORK ARCHITECTURE, RAM & ZERO TRUST PERIMETER
# ==============================================================================
@sra_rule("SRA-NET-001", "Network_Architecture")
def check_vpc_peering_threshold(env: Dict[str, object]) -> bool:
    return not (env["connectivity_pattern"] == "vpc_peering" and env["vpc_count"] >= 10)


@sra_rule("SRA-NET-002", "Network_Architecture")
def check_ram_minimum_blast_radius(env: Dict[str, object]) -> bool:
    return not env["ram_shared_with_entire_org"] and (
        not env["ram_has_external_accounts"] or env["ram_external_invitation_accepted"]
    )


@sra_rule("SRA-NET-003", "Network_Architecture")
def check_network_firewall_dedicated_subnet_and_azs(env: Dict[str, object]) -> bool:
    return (
        not env["other_resources_in_firewall_subnet"]
        and env["firewall_endpoints_in_every_az"]
        and env["dns_firewall_blocks_exfiltration"]
    )


@sra_rule("SRA-ZT-001", "Zero_Trust_Access")
def check_verified_access_and_vpc_lattice(env: Dict[str, object]) -> bool:
    return (
        env["verified_access_identity_and_device_posture"]
        and env["verified_access_logs_to_log_archive"]
        and env["alb_scheme"] == "internal"
        and env["vpc_lattice_iam_auth_enforced"]
    )


# ==============================================================================
# DOMAIN 3: EDGE SECURITY, CLOUDFRONT OAC, WAF FINOPS & ACM
# ==============================================================================
@sra_rule("SRA-EDGE-001", "Edge_Security")
def check_cloudfront_oac_and_anti_bypass(env: Dict[str, object]) -> bool:
    return (
        env["tls_version"] == "TLS 1.3"
        and env["s3_origin_endpoint_mode"] == "rest"
        and env["s3_access_control"] == "OAC"
        and env["s3_block_public_access"]
        and (env["uses_rotated_secret_header_waf"] or env["uses_cloudfront_prefix_list"])
    )


@sra_rule("SRA-EDGE-002", "Edge_Security")
def check_acm_cloudfront_region_and_waf_finops(env: Dict[str, object]) -> bool:
    return (
        env["cloudfront_acm_region"] == "us-east-1"
        and env["acm_same_account_as_resource"]
        and env["firewall_manager_delegated_admin"] == "security-tooling"
        and len(env["waf_resources_in_single_flow"]) == 1
    )


# ==============================================================================
# DOMAIN 4: COMPUTE HARDENING, NITRO ENCLAVES, DATA & CRYPTOGRAPHY
# ==============================================================================
@sra_rule("SRA-CMP-001", "Compute_Hardening")
def check_ec2_and_nitro_enclave_isolation(env: Dict[str, object]) -> bool:
    return (
        env["ec2_imdsv2_required"]
        and env["ec2_in_private_subnet"]
        and env["ebs_default_encryption"]
        and not env["ssh_open_to_internet"]
        and env["nitro_enclave_root_blocked"]
        and env["nitro_kms_attestation_verified"]
    )


@sra_rule("SRA-DAT-001", "Data_And_Cryptography")
def check_aurora_kms_secrets_and_post_quantum(env: Dict[str, object]) -> bool:
    return (
        env["aurora_private_subnet_group"]
        and env["aurora_iam_db_auth"]
        and not env["hardcoded_credentials_detected"]
        and env["secrets_auto_rotation_enabled"]
        and env["kms_cmk_auto_rotation_enabled"]
        and env["hybrid_post_quantum_tls_ml_kem"]
    )


# ==============================================================================
# DOMAIN 5: MULTI-REGION DECISION, PREREQUISITES & 6-PHASE IMPLEMENTATION
# ==============================================================================
@sra_rule("SRA-REG-001", "Multi_Region_Governance")
def check_multi_region_justification_and_prerequisites(env: Dict[str, object]) -> bool:
    if env["deployment_topology"] == "multi-region" and not env["has_regulatory_or_dr_driver"]:
        return False
    required_exemptions = {"iam", "cloudfront", "route53", "shield", "ce"}
    return (
        required_exemptions.issubset(env["scp_exempted_global_services"])
        and env["kms_multi_region_keys_replicated"]
        and env["aws_config_active_all_accounts_mgmt"]
        and env["scp_char_length"] <= 10240
    )


@sra_rule("SRA-OPS-001", "Traceability_And_IR")
def check_central_telemetry_and_six_phase_readiness(env: Dict[str, object]) -> bool:
    required_tags = {"data_classification", "business_criticality"}
    return (
        env["single_multi_region_org_trail"]
        and env["security_hub_single_home_aggregation"]
        and env["guardduty_log_archive_cmk_encrypted"]
        and env["detective_org_automated"]
        and required_tags.issubset(set(env["workload_tags"].keys()))
    )


# ==============================================================================
# MASTER ORCHESTRATOR ENGINE
# ==============================================================================
class MasterSRAComplianceEngine:
    """Executes all registered AWS SRA architectural rules and generates an executive audit report."""

    def __init__(self, rules: List[Dict[str, object]] = RULE_REGISTRY) -> None:
        self.rules = rules

    def evaluate(self, environment_state: Dict[str, object]) -> Dict[str, object]:
        passed_rules: List[str] = []
        failed_rules: List[Dict[str, str]] = []

        for rule in self.rules:
            rule_id = str(rule["id"])
            domain = str(rule["domain"])
            severity = str(rule["severity"])
            check_fn = rule["check"]
            try:
                is_compliant = bool(check_fn(environment_state))
            except KeyError as missing_key:
                is_compliant = False
                failed_rules.append({
                    "rule_id": rule_id,
                    "domain": domain,
                    "severity": severity,
                    "reason": f"Missing telemetry attribute: {missing_key}",
                })
                continue

            if is_compliant:
                passed_rules.append(rule_id)
            else:
                failed_rules.append({
                    "rule_id": rule_id,
                    "domain": domain,
                    "severity": severity,
                    "reason": "Architectural guardrail or RFC 2119 MUST/SHOULD condition violated",
                })

        total = len(self.rules)
        score = round((len(passed_rules) / total) * 100, 2) if total else 0.0
        return {
            "engine": "AWS_SRA_MASTER_COMPLIANCE_ENGINE",
            "overall_status": "COMPLIANT" if not failed_rules else "NON_COMPLIANT",
            "compliance_score_percent": score,
            "total_rules_evaluated": total,
            "passed_count": len(passed_rules),
            "failed_count": len(failed_rules),
            "passed_rules": passed_rules,
            "failed_rules": failed_rules,
        }


# ==============================================================================
# PRODUCTION VERIFICATION SUITE
# ==============================================================================
def build_compliant_enterprise_baseline() -> Dict[str, object]:
    return {
        "manual_iam_users_count": 0,
        "centralized_root_management_active": True,
        "idc_delegated_admin_account": "222233334444",
        "managed_ad_account": "222233334444",
        "idc_mfa_enforced": True,
        "uses_wildcard_resource_arn": False,
        "automated_policy_exception_workflow": True,
        "apps_per_account": 1,
        "shares_roles_or_datastores": False,
        "connectivity_pattern": "transit_gateway",
        "vpc_count": 48,
        "ram_shared_with_entire_org": False,
        "ram_has_external_accounts": True,
        "ram_external_invitation_accepted": True,
        "other_resources_in_firewall_subnet": False,
        "firewall_endpoints_in_every_az": True,
        "dns_firewall_blocks_exfiltration": True,
        "verified_access_identity_and_device_posture": True,
          
