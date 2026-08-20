# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later


from datetime import datetime
from typing import Optional

import click
from blinker import Signal
from cap_tools.models import Alert
from httpx import URL

from capmesh.app_context import AppContext
from capmesh.core import IPAWSSource


@click.command(name="simple-command")
@click.argument("some_argument", type=str)
@click.option(
  "--some-option",
  type=click.DateTime(formats=["%Y-%m-%d"]),
  help="Some option",
)
@click.pass_context
def simple_command(
  ctx: click.Context,
  some_option: Optional[datetime] = None,
  some_argument: Optional[str] = "default_value",
) -> None:
  """
  This is a simple command.
  """
  if some_argument == "sendit":
    try:
      app_context: AppContext = ctx.obj
      app_context.logger.info("Context Online")

      urls: URL = URL(
        "https://tdl.apps.fema.gov/IPAWSOPEN_EAS_SERVICE/rest/public/recent/2024-02-15T12:00:00Z"
      )
      with IPAWSSource(urls, Signal()) as source:
        mydata: list[Alert] = source.parse(source.fetch())
        app_context.logger.debug(f"Length of alert list{(len(mydata))}")

    except Exception as e:
      click.echo(f"CLI Error: {str(e)}")
      ctx.exit(1)

  if some_argument == "test":
    ctx.exit(1)

  ctx.exit(0)
