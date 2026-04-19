import unittest
from pathlib import Path

from vanta.cli import _controller_path


class PackagingTests(unittest.TestCase):
    def test_controller_path_points_to_python_module(self):
        path = _controller_path()

        self.assertTrue(path.endswith("ultimate_mtd_controller.py"))

    def test_packaged_templates_exist(self):
        template_dir = Path(__file__).resolve().parent.parent / "vanta" / "templates"

        self.assertTrue((template_dir / "dashboard_ultimate.html").exists())
        self.assertTrue((template_dir / "login.html").exists())


if __name__ == "__main__":
    unittest.main()
