from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class DeploymentProfile:
    mode: str
    description: str
    supports_remote_agents: bool
    requires_device_trust: bool
    segmentation_model: str
    telemetry_level: str

    def to_dict(self):
        return asdict(self)


DEPLOYMENT_PROFILES = {
    "baseline": DeploymentProfile(
        mode="baseline",
        description="Controlled baseline profile for Mininet-backed lab reproduction.",
        supports_remote_agents=False,
        requires_device_trust=False,
        segmentation_model="controller-centric",
        telemetry_level="research",
    ),
    "adaptive": DeploymentProfile(
        mode="adaptive",
        description="Comparative research profile with richer trust and remote-observer signals.",
        supports_remote_agents=True,
        requires_device_trust=True,
        segmentation_model="policy-zones",
        telemetry_level="comparative",
    ),
    "stress": DeploymentProfile(
        mode="stress",
        description="Stress-test profile for aggressive evaluation of control-plane reactions.",
        supports_remote_agents=True,
        requires_device_trust=True,
        segmentation_model="microsegmented-zones",
        telemetry_level="high",
    ),
}


def load_deployment_profile(mode):
    aliases = {
        "lab": "baseline",
        "hybrid": "adaptive",
        "enterprise": "stress",
    }
    canonical_mode = aliases.get(mode, mode)
    return DEPLOYMENT_PROFILES.get(canonical_mode, DEPLOYMENT_PROFILES["baseline"])
