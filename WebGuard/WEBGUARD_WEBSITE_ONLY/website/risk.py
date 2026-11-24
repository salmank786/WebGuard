"""Conservative, explainable WebGuard risk classification.

These are triage levels, not proof that a site is secure or vulnerable. Findings
from passive checks remain unconfirmed unless a caller explicitly supplies
confirmed=True based on separate verification.
"""
from enum import Enum
from collections import Counter


class RiskLevel(str, Enum):
    HIGH = "High Risk"
    MODERATE = "Moderate Risk"
    LOW = "Low Risk"
    NONE = "No Risk Indicators Detected"


ORDER = [RiskLevel.HIGH.value, RiskLevel.MODERATE.value,
         RiskLevel.LOW.value, RiskLevel.NONE.value]


def classify_finding(finding: dict) -> dict:
    """Add risk_level and risk_reason to a finding without overstating evidence."""
    item = dict(finding)
    kind = str(item.get("type", item.get("reason", ""))).lower()
    severity = str(item.get("severity", item.get("risk", ""))).lower()
    confidence = str(item.get("confidence", "")).lower()
    confirmed = bool(item.get("confirmed", False))

    if confirmed:
        level = RiskLevel.HIGH
        reason = "Marked confirmed by a separate verification process; review evidence and scope."
    elif any(s in kind for s in ("script-capable url", "reflected in raw html", "query value reflected", "unescaped")):
        level = RiskLevel.MODERATE
        reason = "Potentially dangerous or reflected input indicator; browser context and exploitability are not confirmed."
    elif any(s in kind for s in ("content-security-policy", "inline event handler", "execution sink", "document.write", "eval usage", "dynamic function", "string-based timer")):
        level = RiskLevel.LOW
        reason = "Hardening or code-review indicator; this observation alone does not establish an exploitable vulnerability."
    elif any(s in kind for s in ("orphan", "not linked", "404", "broken link")):
        level = RiskLevel.LOW
        reason = "Potential page-discovery or availability issue; verify reachability and intended linking."
    elif any(s in severity for s in ("high", "critical")) and any(s in confidence for s in ("confirmed", "verified")):
        level = RiskLevel.HIGH
        reason = "High-severity finding explicitly marked verified."
    elif any(s in severity for s in ("review", "moderate", "warning")):
        level = RiskLevel.MODERATE
        reason = "Requires manual review; the current evidence is not a confirmed vulnerability."
    elif any(s in severity for s in ("hardening", "low", "informational")):
        level = RiskLevel.LOW
        reason = "Low-priority observation or security-hardening recommendation."
    else:
        level = RiskLevel.LOW
        reason = "Unmapped finding defaults to low-priority review rather than assuming a severe vulnerability."

    item["risk_level"] = level.value
    item["risk_reason"] = reason
    return item


def classify_findings(findings) -> list[dict]:
    return [classify_finding(x) for x in findings]


def risk_counts(findings) -> dict[str, int]:
    counts = Counter(x.get("risk_level", RiskLevel.NONE.value) for x in findings)
    return {level: int(counts.get(level, 0)) for level in ORDER}


def overall_risk(findings) -> str:
    """Highest triage category among findings; empty findings means no indicators detected."""
    levels = {x.get("risk_level", RiskLevel.NONE.value) for x in findings}
    for level in ORDER[:-1]:
        if level in levels:
            return level
    return RiskLevel.NONE.value
