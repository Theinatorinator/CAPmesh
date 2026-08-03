# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from click.testing import CliRunner

from capmesh.cli.__main__ import cli


def test_subcommand_help(cli_runner: CliRunner, cli_env: None) -> None:
    """Test help for subcommand"""
    result = cli_runner.invoke(cli, ["subcommand", "--help"])
    assert result.exit_code == 0
    assert "subcommand [OPTIONS] COMMAND [ARGS]" in result.output
