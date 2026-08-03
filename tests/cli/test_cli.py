# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from click.testing import CliRunner

from capmesh.cli.__main__ import cli


def test_cli_invalid_command(cli_runner: CliRunner, cli_env: None) -> None:
  """Test invalid command handling"""
  result = cli_runner.invoke(cli, ["invalid"])
  assert result.exit_code != 0
  assert "No such command" in result.output


def test_cli_help(cli_runner: CliRunner, cli_env: None) -> None:
  """Test help command"""
  result = cli_runner.invoke(cli, ["--help"])
  assert result.exit_code == 0
  assert "Usage:" in result.output
  assert "Options:" in result.output
