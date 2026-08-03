# SPDX-FileCopyrightText: 2026 Logan Mamanakis Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import click

from capmesh.cli.subcommand.subsubcommand import subsubcommand


@click.group()
@click.pass_context
def subcommand(
    ctx: click.Context,
) -> None:
    """
    This contains sub-subcommands
    """


subcommand.add_command(subsubcommand, name="subsub")
