from dataclasses import dataclass, field


TRUST_SCORES = {
    "untrusted": 0,
    "unknown": 1,
    "managed": 3,
    "verified": 5,
}


@dataclass
class AccessContext:
    username: str
    role: str
    source_ip: str
    user_agent: str
    requested_resource: str
    device_id: str = ""
    device_trust: str = "unknown"
    mfa_verified: bool = False
    deployment_mode: str = "lab"
    remote_access: bool = False


@dataclass
class AccessDecision:
    allowed: bool
    risk_score: int
    trust_score: int
    segmentation_profile: str
    reasons: list[str] = field(default_factory=list)
    required_controls: list[str] = field(default_factory=list)


class ZeroTrustAccessPolicy:
    """Research-friendly policy model for control-plane access experiments."""

    def __init__(self, require_mfa_for_admin=True):
        self.require_mfa_for_admin = require_mfa_for_admin

    def verify_mfa(self, submitted_code, expected_code):
        if not expected_code:
            return True
        return bool(submitted_code) and submitted_code == expected_code

    def evaluate(self, context: AccessContext):
        reasons = []
        required_controls = []
        trust_score = TRUST_SCORES.get(context.device_trust.lower(), TRUST_SCORES["unknown"])
        risk_score = max(0, 5 - trust_score) * 10

        sensitive_resource = any(
            token in context.requested_resource
            for token in ("/api/strategy", "/api/morph", "/api/export", "/api/access")
        )

        if context.remote_access and context.deployment_mode in {"adaptive", "stress", "hybrid", "enterprise"}:
            risk_score += 10
            reasons.append("Remote access path detected")

        if context.role == "admin":
            risk_score += 10
            reasons.append("Administrative access requested")

        if sensitive_resource:
            risk_score += 10
            reasons.append("Sensitive control-plane resource requested")

        if context.device_trust.lower() in {"unknown", "untrusted"}:
            required_controls.append("verified_device")
            reasons.append("Device posture is not strongly trusted")

        if self.require_mfa_for_admin and context.role == "admin" and not context.mfa_verified:
            required_controls.append("mfa")
            risk_score += 25
            reasons.append("Admin action requires MFA")

        if trust_score >= 4 and context.role == "admin":
            segmentation_profile = "admin-zone"
        elif trust_score >= 3:
            segmentation_profile = "user-zone"
        else:
            segmentation_profile = "quarantine-zone"

        allowed = risk_score < 60 and "mfa" not in required_controls
        return AccessDecision(
            allowed=allowed,
            risk_score=risk_score,
            trust_score=trust_score,
            segmentation_profile=segmentation_profile,
            reasons=reasons,
            required_controls=required_controls,
        )
