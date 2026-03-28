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
    "lab": DeploymentProfile(
        mode="lab",
        description="Single-site lab deployment for Mininet and SDN testing.",
        supports_remote_agents=False,
        requires_device_trust=False,
        segmentation_model="controller-centric",
        telemetry_level="research",
    ),
    "hybrid": DeploymentProfile(
        mode="hybrid",
        description="Hybrid enterprise mode with remote operator access and device trust checks.",
        supports_remote_agents=True,
        requires_device_trust=True,
        segmentation_model="policy-zones",
        telemetry_level="operational",
    ),
    "enterprise": DeploymentProfile(
        mode="enterprise",
        description="Enterprise profile with stricter posture-aware access to control-plane actions.",
        supports_remote_agents=True,
        requires_device_trust=True,
        segmentation_model="microsegmented-zones",
        telemetry_level="high",
    ),
}


def load_deployment_profile(mode):
    return DEPLOYMENT_PROFILES.get(mode, DEPLOYMENT_PROFILES["lab"])
