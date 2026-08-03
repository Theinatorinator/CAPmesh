# SPDX-FileCopyrightText: 2026 Logan Mamanakis Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Test capmesh."""

import capmesh


def test_import() -> None:
    """Test that the package can be imported."""
    assert isinstance(capmesh.__name__, str)
