from dataclasses import dataclass
import os


@dataclass(frozen=True)
class RuntimeConfig:
    secret_key: str
    admin_username: str
    admin_password: str
    session_lifetime_hours: int = 24
    deployment_mode: str = "baseline"
    require_mfa_for_admin: bool = True
    default_mfa_code: str = "246810"


def load_runtime_config():
    return RuntimeConfig(
        secret_key=os.getenv(
            "VANTA_SECRET_KEY",
            "vanta-lab-secret-key",
        ),
        admin_username=os.getenv("VANTA_ADMIN_USERNAME", "admin"),
        admin_password=os.getenv("VANTA_ADMIN_PASSWORD", "mtd2024"),
        session_lifetime_hours=int(os.getenv("VANTA_SESSION_LIFETIME_HOURS", "24")),
        deployment_mode=os.getenv("VANTA_DEPLOYMENT_MODE", "baseline"),
        require_mfa_for_admin=os.getenv("VANTA_REQUIRE_MFA_FOR_ADMIN", "true").lower() == "true",
        default_mfa_code=os.getenv("VANTA_MFA_CODE", "246810"),
    )


def build_user_store(hash_password, config=None):
    runtime = config or load_runtime_config()
    return {
        runtime.admin_username: {
            "password": hash_password(runtime.admin_password),
            "role": "admin",
        }
    }
