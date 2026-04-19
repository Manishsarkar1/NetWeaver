from dataclasses import dataclass
import os
from pathlib import Path


def _default_hardware_inventory_path():
    packaged = Path(__file__).resolve().parent.parent / "vanta" / "defaults" / "hardware_inventory.json"
    if packaged.exists():
        return str(packaged)
    repo_local = Path(__file__).resolve().parent.parent / "config" / "hardware_inventory.json"
    return str(repo_local)


@dataclass(frozen=True)
class RuntimeConfig:
    secret_key: str
    admin_username: str
    admin_password: str
    session_lifetime_hours: int = 24
    deployment_mode: str = "hybrid"
    require_mfa_for_admin: bool = True
    default_mfa_code: str = "246810"
    network_backend: str = "ryu_openflow"
    network_target: str = "mininet"
    hardware_inventory_path: str = _default_hardware_inventory_path()
    hardware_rollout_mode: str = "enforce"
    vip_mapping_backend: str = "memory"
    vip_persistence_ttl_seconds: int = 60
    redis_url: str = "redis://localhost:6379/0"
    redis_key_prefix: str = "vanta:vip"
    redis_socket_timeout_seconds: int = 2


def load_runtime_config():
    return RuntimeConfig(
        secret_key=os.getenv(
            "VANTA_SECRET_KEY",
            "mtd-ultra-secret-key-2024-change-in-production",
        ),
        admin_username=os.getenv("VANTA_ADMIN_USERNAME", "admin"),
        admin_password=os.getenv("VANTA_ADMIN_PASSWORD", "mtd2024"),
        session_lifetime_hours=int(os.getenv("VANTA_SESSION_LIFETIME_HOURS", "24")),
        deployment_mode=os.getenv("VANTA_DEPLOYMENT_MODE", "hybrid"),
        require_mfa_for_admin=os.getenv("VANTA_REQUIRE_MFA_FOR_ADMIN", "true").lower() == "true",
        default_mfa_code=os.getenv("VANTA_MFA_CODE", "246810"),
        network_backend=os.getenv("VANTA_NETWORK_BACKEND", "ryu_openflow").lower(),
        network_target=os.getenv("VANTA_NETWORK_TARGET", "mininet").lower(),
        hardware_inventory_path=os.getenv(
            "VANTA_HARDWARE_INVENTORY_PATH",
            _default_hardware_inventory_path(),
        ),
        hardware_rollout_mode=os.getenv(
            "VANTA_HARDWARE_ROLLOUT_MODE",
            "enforce",
        ).lower(),
        vip_mapping_backend=os.getenv("VANTA_VIP_MAPPING_BACKEND", "memory").lower(),
        vip_persistence_ttl_seconds=int(
            os.getenv("VANTA_VIP_PERSISTENCE_TTL_SECONDS", "60")
        ),
        redis_url=os.getenv("VANTA_REDIS_URL", "redis://localhost:6379/0"),
        redis_key_prefix=os.getenv("VANTA_REDIS_KEY_PREFIX", "vanta:vip"),
        redis_socket_timeout_seconds=int(
            os.getenv("VANTA_REDIS_SOCKET_TIMEOUT_SECONDS", "2")
        ),
    )


def build_user_store(hash_password, config=None):
    runtime = config or load_runtime_config()
    return {
        runtime.admin_username: {
            "password": hash_password(runtime.admin_password),
            "role": "admin",
        }
    }
