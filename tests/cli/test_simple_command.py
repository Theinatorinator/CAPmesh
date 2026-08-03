# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest.mock import patch

from click.testing import CliRunner

from capmesh.cli.__main__ import cli


def test_simple_command_help(cli_runner: CliRunner, cli_env: None) -> None:
    """Test help command"""
    result = cli_runner.invoke(cli, ["simple-command", "--help"])
    assert result.exit_code == 0
    assert "simple-command [OPTIONS] SOME_ARGUMENT" in result.output


def test_simple_command_exception_handling(cli_runner: CliRunner, cli_env: None) -> None:
    """Test exception handling when app_context access fails"""
    # Mock the ctx.obj to raise an exception when accessed
    with patch("capmesh.cli.simple_command.click.echo") as mock_echo:
        mock_echo.side_effect = Exception("Mocked exception")

        result = cli_runner.invoke(cli, ["simple-command", "test_arg"], obj=None)

        # The command should exit with code 1 due to the exception
        assert result.exit_code == 1
