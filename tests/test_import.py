"""Test capmesh."""

import capmesh


def test_import() -> None:
    """Test that the package can be imported."""
    assert isinstance(capmesh.__name__, str)
