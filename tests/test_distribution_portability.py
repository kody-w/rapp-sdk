from __future__ import annotations

import shutil
import unittest
from pathlib import Path
from unittest import mock

from tests.distribution_install_smoke import (
    PINNED_SETUPTOOLS_VERSION,
    BackendInfo,
    _backend_overlay,
    _select_backend_site,
)


class DistributionPortabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(__file__).resolve().parent / ".scratch-backend"
        shutil.rmtree(self.scratch, ignore_errors=True)
        self.scratch.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.scratch, ignore_errors=True)

    def test_missing_bundled_setuptools_selects_explicit_local_provider(
        self,
    ) -> None:
        provider = Path("/local/build-backend")
        self.assertEqual(
            _select_backend_site(None, provider),
            provider.resolve(),
        )
        with self.assertRaisesRegex(RuntimeError, "provide --setuptools-site"):
            _select_backend_site(None, None)

    def test_wrong_bundled_version_is_overridden_only_explicitly(self) -> None:
        bundled = BackendInfo("70.0.0", Path("/venv/site-packages"))
        provider = Path("/local/build-backend")
        self.assertEqual(
            _select_backend_site(bundled, provider),
            provider.resolve(),
        )
        with self.assertRaisesRegex(RuntimeError, "no provider"):
            _select_backend_site(bundled, None)

    def test_pinned_bundled_backend_needs_no_provider(self) -> None:
        bundled = BackendInfo(
            PINNED_SETUPTOOLS_VERSION,
            Path("/venv/site-packages"),
        )
        self.assertIsNone(_select_backend_site(bundled, None))

    def test_backend_overlay_excludes_unrelated_site_packages(self) -> None:
        provider = self.scratch / "provider"
        for name in (
            "setuptools",
            "_distutils_hack",
            "pkg_resources",
            f"setuptools-{PINNED_SETUPTOOLS_VERSION}.dist-info",
            "pip",
        ):
            directory = provider / name
            directory.mkdir(parents=True)
            (directory / "marker").write_text(name, encoding="utf-8")
        with mock.patch(
            "tests.distribution_install_smoke.WORK",
            self.scratch / "work",
        ):
            overlay = _backend_overlay(provider)
        self.assertTrue((overlay / "setuptools").is_dir())
        self.assertFalse((overlay / "pip").exists())


if __name__ == "__main__":
    unittest.main()
