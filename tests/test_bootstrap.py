import unittest


class BootstrapTests(unittest.TestCase):
    def test_adcp_package_imports(self) -> None:
        import adcp

        self.assertIsNotNone(adcp)
