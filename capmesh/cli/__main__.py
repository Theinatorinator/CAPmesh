# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
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

from capmesh import __version__
from capmesh.app_context import AppContext
from capmesh.cli.simple_command import simple_command
from capmesh.cli.source import source
from capmesh.cli.subcommand import subcommand

CONTEXT_SETTINGS = dict(
  help_option_names=["-h", "--help"], default_map={"obj": {}}
)


console = Console()


@click.version_option(__version__, "--version", "-v")
@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
def cli(ctx: click.Context) -> None:
  """
  Main entry point for the CLI.
  """
  # Putting all objects in context so that they don't have to be
  # recreated for each command
  ctx.ensure_object(AppContext)


cli.add_command(cmd=subcommand)
cli.add_command(cmd=simple_command)
cli.add_command(cmd=source)

if __name__ == "__main__":
  cli()
