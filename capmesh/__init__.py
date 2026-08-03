# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

__app_name__ = "CAPmesh"

import importlib.metadata

try:
  __version__: str = importlib.metadata.version(distribution_name=__app_name__)
except (importlib.metadata.PackageNotFoundError, AttributeError, IndexError):
  __version__ = "0.0.0-unknown"

# Explicitly define what is exposed when importing from the package root
__all__: list[str] = ["__version__"]
