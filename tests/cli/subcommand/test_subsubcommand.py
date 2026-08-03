# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest.mock import patch

from click.testing import CliRunner

from capmesh.cli.__main__ import cli


def test_subsub_help(cli_runner: CliRunner, cli_env: None) -> None:
  """Test help for subsubcommand"""
  result = cli_runner.invoke(cli, ["subcommand", "subsub", "--help"])
  assert result.exit_code == 0
  assert "subcommand subsub [OPTIONS] SOME_ARGUMENT" in result.output


def test_subsub_exception_handling(
  cli_runner: CliRunner, cli_env: None
) -> None:
  """Test exception handling when app_context access fails"""
  with patch("capmesh.cli.subcommand.subsubcommand.click.echo") as mock_echo:
    mock_echo.side_effect = Exception("Mocked exception")

    result = cli_runner.invoke(
      cli, ["subcommand", "subsub", "test_arg"], obj=None
    )

    assert result.exit_code == 1
