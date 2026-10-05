import json
from typing import Any, Dict, List, Optional

# Baseline rules expected for student AI project compliance auditing
NXTWAVE_BASELINE_RULES = {
    "nxtwave-hardcoded-secret",
    "nxtwave-raw-prompt-injection",
    "nxtwave-missing-try-except",
    "nxtwave-sql-injection",
    "nxtwave-command-injection",
    "nxtwave-path-traversal",
    "nxtwave-unsafe-deserialization",
    "nxtwave-weak-crypto",
    "nxtwave-insecure-randomness",
    "nxtwave-tls-verification-disabled",
    "nxtwave-debug-enabled",
    "nxtwave-permissive-cors",
    "nxtwave-insecure-cookie",
    "nxtwave-unsafe-redirect",
    "nxtwave-sensitive-logging",
    "nxtwave-dangerous-eval",
    "nxtwave-llm-output-execution",
    "nxtwave-llm-tool-without-authorization",
    "nxtwave-unbounded-upload",
    "nxtwave-unpinned-dependency",
    "nxtwave-container-root-user",
    "nxtwave-private-data-in-prompt",
}

NXTWAVE_RULE_PRIORITIES = {
    "nxtwave-hardcoded-secret": "critical",
    "nxtwave-raw-prompt-injection": "high",
    "nxtwave-missing-try-except": "high",
    "nxtwave-sql-injection": "critical",
    "nxtwave-command-injection": "critical",
    "nxtwave-path-traversal": "critical",
    "nxtwave-unsafe-deserialization": "critical",
    "nxtwave-weak-crypto": "high",
    "nxtwave-insecure-randomness": "high",
    "nxtwave-tls-verification-disabled": "critical",
    "nxtwave-debug-enabled": "high",
    "nxtwave-permissive-cors": "high",
    "nxtwave-insecure-cookie": "critical",
    "nxtwave-unsafe-redirect": "high",
    "nxtwave-sensitive-logging": "high",
    "nxtwave-dangerous-eval": "critical",
    "nxtwave-llm-output-execution": "critical",
    "nxtwave-llm-tool-without-authorization": "critical",
    "nxtwave-unbounded-upload": "high",
    "nxtwave-unpinned-dependency": "high",
    "nxtwave-container-root-user": "high",
    "nxtwave-private-data-in-prompt": "critical",
}

_MANUAL_CONTROL_GROUPS = {
    "Authentication": [
        "Strong passwords", "Minimum password length", "Password complexity", "No plaintext passwords",
        "Argon2, bcrypt, or scrypt password hashing", "Account lockout or login rate limiting", "MFA",
        "Secure password reset", "No username or email enumeration", "Inactive-session expiration",
    ],
    "Authorization and Access Control": [
        "Least privilege", "Resource-level access restrictions", "RBAC", "Admin and user privilege separation",
        "Server-side authorization", "Protection against IDOR and URL tampering", "Deny-by-default access",
        "Privilege review and revocation",
    ],
    "Input Validation": [
        "Validation of all user input", "Allowlists", "Type, length, format, and range validation",
        "Output sanitization", "Server-side validation", "LDAP injection prevention",
    ],
    "Web Application Security": [
        "XSS protection", "CSRF protection", "Authentication-bypass protection", "Session-hijacking protection",
        "Clickjacking protection", "No sensitive data in URLs", "Unneeded HTTP methods disabled",
        "Security headers", "Generic user-facing errors",
    ],
    "Session Security": [
        "Secure session identifiers", "Session-ID regeneration after login", "Session expiration",
        "Logout invalidation", "Secure cookies", "HttpOnly cookies", "SameSite cookies",
        "Session-fixation protection", "No sensitive client-side session data",
    ],
    "Encryption and Data Protection": [
        "HTTPS/TLS", "No passwords over HTTP", "Encryption at rest", "Modern cryptography",
        "No custom cryptography", "Separate encryption-key storage", "No hardcoded encryption keys",
        "No secrets in source or Git",
    ],
    "Database Security": [
        "Least-privilege database accounts", "Prepared statements", "Sensitive-field encryption",
        "Restricted database network access", "No unnecessary public database exposure", "Regular backups",
        "Encrypted backups", "Database access auditing", "Default credentials removed",
    ],
    "API Security": [
        "API authentication", "API authorization", "API input validation", "API rate limiting",
        "HTTPS APIs", "No internal implementation exposure", "Minimum necessary response data",
        "Parameter validation", "API abuse protection", "Request-size limits",
    ],
    "File Security": [
        "File validation", "Extension restrictions", "Content-type verification", "Upload-size limits",
        "Non-executable upload storage", "Server-generated filenames", "Directory-traversal prevention",
        "Malware scanning", "Access control for uploaded files",
    ],
    "Logging and Monitoring": [
        "Authentication-event logging", "Privilege-change logging", "Administrative-action logging",
        "Suspicious-request logging", "Security-error logging", "Timestamped logs", "Tamper-resistant logs",
        "No passwords in logs", "No keys or tokens in logs", "Failed-login monitoring", "Critical-event alerts",
    ],
    "Network Security": [
        "Firewalls", "Closed unnecessary ports", "Network segmentation", "Secure protocols", "No Telnet",
        "SFTP or FTPS instead of unencrypted FTP", "Restricted management interfaces", "Network monitoring",
        "Unusual-traffic detection", "Inter-segment access control",
    ],
    "Secure Software Development": [
        "Secure coding practices", "Updated dependencies", "Unused-library removal", "Dependency vulnerability scanning",
        "Code review", "Static analysis", "Environment separation", "No hardcoded credentials",
        "Secret management", "Pre-deployment security testing",
    ],
    "Error Handling": [
        "No database errors exposed", "No source code exposed", "No internal paths exposed",
        "Generic user errors", "Secure server-side detailed logs", "Exception handling",
    ],
    "Backup and Recovery": [
        "Regular backups", "Encrypted sensitive backups", "Restore testing", "Backups separate from production",
        "Documented recovery procedures", "Protection against unauthorized backup deletion",
    ],
    "Privacy": [
        "Necessary-data collection only", "PII protection", "No personal-data API exposure", "Sensitive-data masking",
        "Data deletion", "Restricted PII access",
    ],
    "Security Testing": [
        "Vulnerability scanning", "Authentication testing", "Authorization testing", "SQL-injection testing",
        "XSS testing", "CSRF testing", "Session testing", "File-upload testing", "API testing",
        "Rate-limit testing", "Access-control bypass testing", "Authorized penetration testing",
    ],
}

NXTWAVE_MANUAL_REVIEW_CONTROLS = [
    {
        "category": category,
        "control": control,
        "priority": "critical" if category in {"Authentication", "Authorization and Access Control", "Web Application Security", "Session Security"} else "high",
        "status": "MANUAL_REVIEW",
        "reason": "Requires runtime, deployment, configuration, policy, or authorized dynamic testing.",
    }
    for category, controls in _MANUAL_CONTROL_GROUPS.items()
    for control in controls
]

def format_nxtwave_audit(scan_results: Any, required_rule_ids: Optional[List[str]] = None) -> str:
    """
    Transforms raw Semgrep scan findings into a structured student compliance scorecard
    and JSON audit report based on a gap analysis of required baseline rules.
    """
    baseline = set(required_rule_ids) if required_rule_ids else NXTWAVE_BASELINE_RULES

    # Parse the findings depending on whether it's a full Semgrep JSON dict or a list of matches
    if isinstance(scan_results, dict) and "results" in scan_results:
        results = scan_results["results"]
    elif isinstance(scan_results, list):
        results = scan_results
    else:
        results = []

    total_violations = 0
    violated_rule_ids = set()
    unimplemented_rules = []

    # Map findings to our gap-analysis structure
    for match in results:
        # Support both native Semgrep `check_id` and generic `rule_id`
        rule_id = match.get("check_id") or match.get("rule_id", "")
        if rule_id not in baseline and "." in rule_id:
            rule_id = rule_id.rsplit(".", 1)[-1]

        # Only analyze violations that are part of the required baseline
        if rule_id in baseline:
            total_violations += 1
            violated_rule_ids.add(rule_id)

            # Safely extract standard semgrep finding fields
            path = match.get("path", "")

            start = match.get("start", {})
            line = start.get("line") if isinstance(start, dict) else match.get("line")

            extra = match.get("extra", {})
            severity = extra.get("severity") or match.get("severity", "WARNING")
            message = extra.get("message") or match.get("message", "")

            unimplemented_rules.append({
                "rule_id": rule_id,
                "priority": NXTWAVE_RULE_PRIORITIES.get(rule_id, "high"),
                "file": path,
                "line": line,
                "severity": severity,
                "message": message
            })

    # Gap analysis: passing rules are those in the baseline that had zero violations
    implemented_rules = sorted(list(baseline - violated_rule_ids))

    # Weight critical findings more heavily while keeping the score deterministic.
    total_required = len(baseline)
    rule_weights = {"critical": 3, "high": 2, "medium": 1}
    total_weight = sum(rule_weights.get(NXTWAVE_RULE_PRIORITIES.get(rule_id, "high"), 2) for rule_id in baseline)
    failed_weight = sum(
        rule_weights.get(NXTWAVE_RULE_PRIORITIES.get(rule_id, "high"), 2)
        for rule_id in violated_rule_ids
    )
    compliance_score = int(((total_weight - failed_weight) / total_weight) * 100) if total_weight else 100
    critical_violation = any(
        NXTWAVE_RULE_PRIORITIES.get(rule_id) == "critical"
        for rule_id in violated_rule_ids
    )
    status = "PASSED" if compliance_score >= 90 and not critical_violation else "NEEDS_REVISION"

    priority_summary = {
        priority: {
            "total": sum(1 for rule_id in baseline if NXTWAVE_RULE_PRIORITIES.get(rule_id) == priority),
            "violated": sum(1 for rule_id in violated_rule_ids if NXTWAVE_RULE_PRIORITIES.get(rule_id) == priority),
        }
        for priority in ("critical", "high", "medium")
    }

    audit_report = {
        "compliance_score": compliance_score,
        "status": status,
        "total_violations": total_violations,
        "unimplemented_rules": unimplemented_rules,
        "implemented_rules": implemented_rules,
        "priority_summary": priority_summary,
        "manual_review_required": NXTWAVE_MANUAL_REVIEW_CONTROLS,
        "coverage": {
            "automated_static_rules": len(baseline),
            "manual_review_controls": len(NXTWAVE_MANUAL_REVIEW_CONTROLS),
            "automated_status": "PASSED" if not violated_rule_ids else "NEEDS_REVISION",
        },
        "assessment_note": "Static findings reflect configured patterns only; manual review controls are not proven by a clean scan.",
    }

    return json.dumps(audit_report, indent=2)
