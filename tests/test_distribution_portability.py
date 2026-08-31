from __future__ import annotations

import base64
import csv
import hashlib
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
        bundled = BackendInfo(
            "70.0.0",
            Path("/venv/site-packages"),
            Path("/venv/site-packages/setuptools/build_meta.py"),
        )
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
            Path("/venv/site-packages/setuptools/build_meta.py"),
        )
        self.assertIsNone(_select_backend_site(bundled, None))

    def _provider(self) -> Path:
        provider = self.scratch / "provider"
        shutil.rmtree(provider, ignore_errors=True)
        dist_info = provider / (
            f"setuptools-{PINNED_SETUPTOOLS_VERSION}.dist-info"
        )
        (provider / "setuptools").mkdir(parents=True)
        (provider / "_distutils_hack").mkdir()
        dist_info.mkdir()
        files = {
            "setuptools/__init__.py": "__version__ = '84.0.0'\n",
            "setuptools/build_meta.py": "build_wheel = None\n",
            "_distutils_hack/__init__.py": "",
            f"{dist_info.name}/METADATA": (
                "Metadata-Version: 2.4\n"
                "Name: setuptools\n"
                f"Version: {PINNED_SETUPTOOLS_VERSION}\n"
            ),
            f"{dist_info.name}/top_level.txt": "_distutils_hack\nsetuptools\n",
        }
        rows = []
        for relative, content in files.items():
            path = provider / relative
            path.write_text(content, encoding="utf-8")
            digest = base64.urlsafe_b64encode(
                hashlib.sha256(path.read_bytes()).digest()
            ).rstrip(b"=").decode()
            rows.append(
                [
                    relative,
                    f"sha256={digest}",
                    str(path.stat().st_size),
                ]
            )
        record_relative = f"{dist_info.name}/RECORD"
        rows.append([record_relative, "", ""])
        with (provider / record_relative).open(
            "w",
            newline="",
            encoding="utf-8",
        ) as stream:
            csv.writer(stream).writerows(rows)
        (provider / "pip").mkdir()
        (provider / "pkg_resources").mkdir()
        return provider

    def test_real_wheel_layout_without_pkg_resources_is_supported(self) -> None:
        provider = self._provider()
        with mock.patch(
            "tests.distribution_install_smoke.WORK",
            self.scratch / "work",
        ):
            overlay = _backend_overlay(provider)
        self.assertTrue((overlay / "setuptools").is_dir())
        self.assertTrue((overlay / "_distutils_hack").is_dir())
        self.assertFalse((overlay / "pkg_resources").exists())
        self.assertFalse((overlay / "pip").exists())

    def test_malicious_record_path_and_missing_backend_are_rejected(self) -> None:
        provider = self._provider()
        dist_info = provider / (
            f"setuptools-{PINNED_SETUPTOOLS_VERSION}.dist-info"
        )
        with (dist_info / "RECORD").open(
            "a",
            newline="",
            encoding="utf-8",
        ) as stream:
            csv.writer(stream).writerow(["../escape.py", "", ""])
        with mock.patch(
            "tests.distribution_install_smoke.WORK",
            self.scratch / "work-malicious",
        ), self.assertRaisesRegex(RuntimeError, "unsafe"):
            _backend_overlay(provider)

        provider = self._provider()
        (provider / "setuptools" / "build_meta.py").unlink()
        with mock.patch(
            "tests.distribution_install_smoke.WORK",
            self.scratch / "work-missing",
        ), self.assertRaisesRegex(RuntimeError, "missing"):
            _backend_overlay(provider)

    def test_forged_empty_record_digest_is_rejected(self) -> None:
        provider = self._provider()
        dist_info = provider / (
            f"setuptools-{PINNED_SETUPTOOLS_VERSION}.dist-info"
        )
        record = dist_info / "RECORD"
        with record.open(encoding="utf-8") as stream:
            rows = list(csv.reader(stream))
        rows[0][1:] = ["", ""]
        with record.open("w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows(rows)
        with mock.patch(
            "tests.distribution_install_smoke.WORK",
            self.scratch / "work-empty-digest",
        ), self.assertRaisesRegex(RuntimeError, "lacks hash or size"):
            _backend_overlay(provider)


if __name__ == "__main__":
    unittest.main()
