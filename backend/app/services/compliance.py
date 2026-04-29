from typing import List


def _kw(finding, *keywords: str) -> bool:
    """Case-insensitive keyword search across rule_id, title, and description."""
    haystack = " ".join([
        (finding.rule_id or "").lower(),
        (finding.title or "").lower(),
        (finding.description or "")[:300].lower(),
    ])
    return any(kw in haystack for kw in keywords)


def _type(finding, *types: str) -> bool:
    return (finding.finding_type or "").lower() in types


def _sev(finding, *severities: str) -> bool:
    return (finding.severity or "").lower() in severities


def _scanner(finding, *scanners: str) -> bool:
    return (finding.scanner or "").lower() in scanners


# fmt: off
COMPLIANCE_MAPPINGS = [

    # ── OWASP Top 10 2021 ────────────────────────────────────────────────────

    {
        "framework": "OWASP Top 10 2021",
        "control": "A01 — Broken Access Control",
        "match": lambda f: _kw(f, "access-control", "authz", "authorization", "privilege",
                                "idor", "traversal", "path-traversal", "directory-traversal",
                                "open-redirect", "csrf", "cors", "broken-access",
                                "insecure-direct", "missing-authorization"),
    },
    {
        "framework": "OWASP Top 10 2021",
        "control": "A02 — Cryptographic Failures",
        "match": lambda f: (
            _type(f, "secrets")
            or _kw(f, "md5", "sha1", "des", "rc4", "ecb", "weak-hash", "weak-cipher",
                   "hardcoded-password", "hardcoded-secret", "cleartext", "plaintext",
                   "plain-text-password", "unencrypted", "http-without-tls",
                   "insecure-random", "weak-crypto", "crypto")
        ),
    },
    {
        "framework": "OWASP Top 10 2021",
        "control": "A03 — Injection",
        "match": lambda f: _kw(f, "sql", "injection", "sqli", "xss", "cross-site-scripting",
                                "xxe", "ldap", "nosql", "command-injection", "os-command",
                                "shell-injection", "code-injection", "eval", "exec(",
                                "pickle", "deserializ", "template-injection", "ssti",
                                "ognl", "el-injection", "expression-language"),
    },
    {
        "framework": "OWASP Top 10 2021",
        "control": "A05 — Security Misconfiguration",
        "match": lambda f: (
            _type(f, "iac")
            or _kw(f, "misconfiguration", "debug-mode", "verbose-error", "cors-wildcard",
                   "missing-header", "security-header", "x-frame-options", "content-security-policy",
                   "hsts", "default-credentials", "default-password", "exposed-port",
                   "public-bucket", "public-access", "world-readable")
        ),
    },
    {
        "framework": "OWASP Top 10 2021",
        "control": "A06 — Vulnerable and Outdated Components",
        "match": lambda f: _type(f, "sca", "container"),
    },
    {
        "framework": "OWASP Top 10 2021",
        "control": "A07 — Identification and Authentication Failures",
        "match": lambda f: (
            _type(f, "secrets")
            or _kw(f, "auth", "authentication", "jwt", "token", "session-fixation",
                   "weak-password", "password-policy", "brute-force", "account-lockout",
                   "credential", "api-key", "mfa", "2fa", "insecure-cookie",
                   "session-management", "improper-authentication")
        ),
    },
    {
        "framework": "OWASP Top 10 2021",
        "control": "A08 — Software and Data Integrity Failures",
        "match": lambda f: _kw(f, "deserializ", "pickle", "yaml.load", "marshal",
                                "supply-chain", "dependency-confusion", "typosquat",
                                "integrity-check", "signature-verification", "unsigned"),
    },
    {
        "framework": "OWASP Top 10 2021",
        "control": "A09 — Security Logging & Monitoring Failures",
        "match": lambda f: _kw(f, "logging", "audit-log", "cloudtrail", "cloudwatch",
                                "log-injection", "missing-log", "no-logging",
                                "insufficient-logging", "monitoring"),
    },
    {
        "framework": "OWASP Top 10 2021",
        "control": "A10 — Server-Side Request Forgery",
        "match": lambda f: _kw(f, "ssrf", "server-side-request", "request-forgery",
                                "unsafe-url", "unvalidated-url", "open-redirect"),
    },

    # ── PCI-DSS v4.0 ─────────────────────────────────────────────────────────

    {
        "framework": "PCI-DSS v4.0",
        "control": "Req 2 — Secure Configurations",
        "match": lambda f: (
            _type(f, "iac")
            or _kw(f, "default-password", "default-credential", "insecure-default",
                   "hardcoded", "weak-config", "misconfiguration")
        ),
    },
    {
        "framework": "PCI-DSS v4.0",
        "control": "Req 3 — Protect Stored Account Data",
        "match": lambda f: _kw(f, "encrypt", "aes", "encryption-at-rest", "kms",
                                "unencrypted-storage", "s3-encryption", "rds-encryption",
                                "disk-encryption", "storage-encryption"),
    },
    {
        "framework": "PCI-DSS v4.0",
        "control": "Req 4 — Protect Data in Transit",
        "match": lambda f: _kw(f, "tls", "ssl", "https", "certificate", "cipher-suite",
                                "weak-tls", "tls1.0", "tls1.1", "sslv3",
                                "insecure-protocol", "plaintext-transmission", "http-only"),
    },
    {
        "framework": "PCI-DSS v4.0",
        "control": "Req 6 — Develop and Maintain Secure Systems",
        "match": lambda f: (
            _type(f, "sast") and _sev(f, "critical", "high")
        ),
    },
    {
        "framework": "PCI-DSS v4.0",
        "control": "Req 8 — Identify and Authenticate",
        "match": lambda f: (
            _type(f, "secrets")
            or _kw(f, "weak-password", "password-policy", "mfa", "authentication",
                   "api-key", "jwt", "token", "session", "iam-user", "access-key")
        ),
    },
    {
        "framework": "PCI-DSS v4.0",
        "control": "Req 10 — Log and Monitor",
        "match": lambda f: _kw(f, "logging", "audit", "cloudtrail", "log-group",
                                "access-log", "monitoring", "flow-logs", "vpc-flow"),
    },
    {
        "framework": "PCI-DSS v4.0",
        "control": "Req 11 — Test Security",
        "match": lambda f: _type(f, "sca", "container") and _sev(f, "critical", "high"),
    },

    # ── CIS Benchmarks (Cloud & Container) ───────────────────────────────────

    {
        "framework": "CIS Benchmarks",
        "control": "Section 1 — Identity & Access Management",
        "match": lambda f: (
            _type(f, "iac")
            and _kw(f, "iam", "mfa", "password-policy", "root-account", "access-key",
                    "role", "policy", "least-privilege", "admin", "cross-account",
                    "account-lockout", "inactive-user")
        ),
    },
    {
        "framework": "CIS Benchmarks",
        "control": "Section 2 — Storage",
        "match": lambda f: (
            _type(f, "iac")
            and _kw(f, "s3", "bucket", "blob", "storage", "public-access", "acl",
                    "versioning", "encryption", "object-lock", "data-at-rest")
        ),
    },
    {
        "framework": "CIS Benchmarks",
        "control": "Section 3 — Logging",
        "match": lambda f: (
            _type(f, "iac")
            and _kw(f, "cloudtrail", "cloudwatch", "flow-log", "audit", "logging",
                    "log-group", "retention", "monitoring", "access-log")
        ),
    },
    {
        "framework": "CIS Benchmarks",
        "control": "Section 4 — Networking",
        "match": lambda f: (
            _type(f, "iac")
            and _kw(f, "security-group", "sg-", "nacl", "vpc", "subnet",
                    "public-ip", "open-port", "ingress", "egress",
                    "wildcard-cidr", "0.0.0.0", "::/0", "unrestricted")
        ),
    },
    {
        "framework": "CIS Benchmarks",
        "control": "Section 5 — Compute & Containers",
        "match": lambda f: (
            (_type(f, "iac") and _kw(f, "instance", "ec2", "vm", "compute",
                                     "kubernetes", "k8s", "container", "docker",
                                     "privileged", "root-user", "user-data"))
            or (_type(f, "container") and _sev(f, "critical", "high"))
        ),
    },

    # ── DORA (Digital Operational Resilience Act) ─────────────────────────────

    {
        "framework": "DORA",
        "control": "Art. 5-7 — ICT Risk Management",
        "match": lambda f: _sev(f, "critical", "high") and _type(f, "sast", "sca", "container", "iac"),
    },
    {
        "framework": "DORA",
        "control": "Art. 9 — Protection & Prevention",
        "match": lambda f: (
            _type(f, "iac")
            or (_type(f, "sast") and _kw(f, "injection", "auth", "crypto", "encrypt",
                                          "access-control", "config"))
        ),
    },
    {
        "framework": "DORA",
        "control": "Art. 10 — Detection",
        "match": lambda f: _kw(f, "logging", "monitoring", "cloudtrail", "audit",
                                "detection", "alerting", "siem"),
    },
    {
        "framework": "DORA",
        "control": "Art. 13 — ICT Third-Party Risk",
        "match": lambda f: _type(f, "sca", "container"),
    },
    {
        "framework": "DORA",
        "control": "Art. 25 — Advanced Testing (TLPT)",
        "match": lambda f: _sev(f, "critical") and _type(f, "sast", "sca", "container"),
    },

    # ── SOC 2 Type II ─────────────────────────────────────────────────────────

    {
        "framework": "SOC 2 Type II",
        "control": "CC6.1 — Logical Access Controls",
        "match": lambda f: (
            _type(f, "secrets")
            or _kw(f, "auth", "access-control", "iam", "privilege", "permission",
                   "mfa", "credential", "api-key", "jwt", "session")
        ),
    },
    {
        "framework": "SOC 2 Type II",
        "control": "CC6.6 — Encryption in Transit",
        "match": lambda f: _kw(f, "tls", "ssl", "https", "certificate", "weak-cipher",
                                "plaintext-transmission", "unencrypted-traffic"),
    },
    {
        "framework": "SOC 2 Type II",
        "control": "CC6.8 — Malware & Vulnerability Prevention",
        "match": lambda f: (
            _type(f, "container", "sca")
            or (_type(f, "sast") and _sev(f, "critical", "high"))
        ),
    },
    {
        "framework": "SOC 2 Type II",
        "control": "CC7.1 — Vulnerability Management",
        "match": lambda f: _sev(f, "critical", "high") and f.status == "open",
    },
    {
        "framework": "SOC 2 Type II",
        "control": "CC9.2 — Vendor & Third-Party Risk",
        "match": lambda f: _type(f, "sca", "container"),
    },
]
# fmt: on


def map_finding_to_compliance(finding) -> List[str]:
    """Return compliance tags for a finding, e.g. ['OWASP Top 10 2021|A03 — Injection']."""
    tags = []
    for mapping in COMPLIANCE_MAPPINGS:
        try:
            if mapping["match"](finding):
                tags.append(f"{mapping['framework']}|{mapping['control']}")
        except Exception:
            pass
    return tags


def apply_compliance_tags(db_session, findings: list) -> int:
    """Apply compliance tags to a list of Finding ORM objects and flush."""
    updated = 0
    for finding in findings:
        tags = map_finding_to_compliance(finding)
        if finding.compliance_tags != tags:
            finding.compliance_tags = tags
            updated += 1
    if updated > 0:
        db_session.flush()
    return updated
