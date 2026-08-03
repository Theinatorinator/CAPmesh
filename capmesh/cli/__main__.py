# SPDX-FileCopyrightText: 2026 Logan Mamanakis Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# CAPmesh/cli/__main__.py

"""
CLI for the App.

for more info, run

```sh
CAPmesh --help
```
"""

import click
from rich.console import Console

from capmesh.app_context import AppContext
from capmesh.cli.simple_command import simple_command
from capmesh.cli.subcommand import subcommand

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], default_map={"obj": {}})


console = Console()


@click.version_option(None, "--version", "-v")
@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """
    Main entry point for the CLI.
    """
    # Putting all objects in context so that they don't have to be
    # recreated for each command
    ctx.ensure_object(AppContext)


cli.add_command(subcommand)
cli.add_command(simple_command)


if __name__ == "__main__":
    cli()
