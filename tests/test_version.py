# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Test capmesh versioning"""

import importlib.metadata
import pathlib
import sys
import tomllib
from unittest.mock import patch

import capmesh


def test_version_is_exposed() -> None:
  """Verify that __version__ is defined at the package root level."""
  assert hasattr(capmesh, "__version__")
  assert isinstance(capmesh.__version__, str)


def test_version_format_or_unknown() -> None:
  """Verify the version string is either a valid version or our safe fallback."""
  version = capmesh.__version__

  # If the package is installed via 'uv run pytest', it should have a real version
  if version != "0.0.0-unknown":
    # Basic check to ensure it follows semantic version formatting (e.g., 1.2.0)
    parts = version.split(".")
    assert len(parts) >= 2, f"Version '{version}' does not look like semver"
  else:
    # If running raw without installation, ensure it uses our precise fallback string
    assert version == "0.0.0-unknown"


def test_version_metadata_fallback() -> None:
  """Force a PackageNotFoundError to prove the fallback logic handles errors gracefully."""
  # Forcefully clear capmesh from loaded modules so we can test the initialization code fresh
  if "capmesh" in sys.modules:
    del sys.modules["capmesh"]

  # Mock importlib.metadata.version to raise a PackageNotFoundError
  with patch(
    "importlib.metadata.version",
    side_effect=importlib.metadata.PackageNotFoundError,
  ):
    import capmesh as reloaded_capmesh

    assert reloaded_capmesh.__version__ == "0.0.0-unknown"


def test_package_matches_pyproject_toml() -> None:
  """Verify capmesh.__version__ explicitly matches the pyproject.toml configuration file."""
  # 1. Locate the pyproject.toml relative to this test file
  # tests/test_version.py -> ../pyproject.toml
  project_root = pathlib.Path(__file__).parent.parent
  toml_path = project_root / "pyproject.toml"

  # Fail cleanly if the pathing configuration is physically broken in your project tree
  assert toml_path.exists(), (
    f"Could not locate project file asset configuration at: {toml_path}"
  )

  # 2. Parse the true configuration file manually
  with open(toml_path, "rb") as f:
    toml_data = tomllib.load(f)

  # Extract the true source of truth target
  expected_version = toml_data.get("project", {}).get("version")
  assert expected_version is not None, (
    "Your [project] section is missing a 'version' definition."
  )

  # 3. Validate against the active module environment payload
  active_version = capmesh.__version__

  # Provide an ultra-descriptive assertion failure error log if they drift out of sync
  assert active_version == expected_version, (
    f"Version Mismatch! Your pyproject.toml defines version '{expected_version}', "
    f"but the runtime package metadata environment is exposing '{active_version}'."
  )
