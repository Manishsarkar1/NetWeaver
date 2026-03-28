import unittest

from vanta_core.access_control import AccessContext, ZeroTrustAccessPolicy
from vanta_core.deployment import load_deployment_profile


class AccessControlTests(unittest.TestCase):
    def test_admin_requires_mfa_for_sensitive_actions(self):
        policy = ZeroTrustAccessPolicy(require_mfa_for_admin=True)
        context = AccessContext(
            username="admin",
            role="admin",
            source_ip="10.0.0.10",
            user_agent="Mozilla/5.0",
            requested_resource="/api/morph/force",
            device_trust="verified",
            mfa_verified=False,
            deployment_mode="hybrid",
            remote_access=True,
        )

        decision = policy.evaluate(context)

        self.assertFalse(decision.allowed)
        self.assertIn("mfa", decision.required_controls)
        self.assertEqual(decision.segmentation_profile, "admin-zone")

    def test_verified_user_device_gets_user_zone(self):
        policy = ZeroTrustAccessPolicy(require_mfa_for_admin=True)
        context = AccessContext(
            username="analyst",
            role="user",
            source_ip="10.0.0.15",
            user_agent="Mozilla/5.0",
            requested_resource="/api/stats",
            device_trust="managed",
            mfa_verified=False,
            deployment_mode="hybrid",
            remote_access=False,
        )

        decision = policy.evaluate(context)

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.segmentation_profile, "user-zone")


class DeploymentProfileTests(unittest.TestCase):
    def test_hybrid_profile_enables_remote_agent_support(self):
        profile = load_deployment_profile("hybrid")

        self.assertTrue(profile.supports_remote_agents)
        self.assertTrue(profile.requires_device_trust)


if __name__ == "__main__":
    unittest.main()
