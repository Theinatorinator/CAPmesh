from capmesh.config.app_config import CapmeshConfig


def test_settings() -> None:
    settings = CapmeshConfig()
    assert settings.app_name == "CAPmesh"
    assert settings.log_level in ["INFO", "DEBUG"]
