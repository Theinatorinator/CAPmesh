from typing import Dict, Optional

import click
from blinker import Signal
from cap_tools.models import Alert
from httpx import URL

from capmesh.app_context import AppContext
from capmesh.core import IPAWSSource
from capmesh.core.types import AlertSource

# 1. Define a Registry mapping your CLI string identifier to the actual Class
SOURCE_REGISTRY: Dict[str, type[AlertSource]] = {
  "ipaws": IPAWSSource,
}


def source_factory(
  source_type: str, uri: str, fresh_data: Signal
) -> AlertSource:
  """Pythonic factory function that resolves and instantiates source classes."""
  source_class: type | None = SOURCE_REGISTRY.get(source_type.lower())

  if not source_class:
    # Click-native exception will cleanly report back to the user
    valid_types: str = ", ".join(f"'{k}'" for k in SOURCE_REGISTRY.keys())
    raise click.BadParameter(
      f"Unsupported source type '{source_type}'. Supported types are: {valid_types}"
    )

  if source_class is IPAWSSource:
    return source_class(feed_url=URL(uri), fresh_data=fresh_data)

  raise NotImplementedError(
    f"Initialization strategy for {source_class.__name__} has not been defined."
  )


@click.group
@click.argument("type", type=str)
@click.pass_context
def source(ctx: click.Context, type: str) -> None:
  ctx.obj.source_type = type
  # All source have a certian set of interfacing conections, we need to decide which one to use though
  # Each method of doing it will be diffrent, but the basic operations will be the same.


@source.command
@click.argument("uri", type=str, required=True)
@click.option("--output", default="stdout")
@click.pass_context
def fetch(ctx: click.Context, output: Optional[str], uri: str) -> None:
  # Somehow we need to be able to declare how to deal with various sources
  # Example, one might handle com ports, one polling, another one another etc.
  # Noting that for future development
  app_context: AppContext = ctx.obj
  app_context.logger.info("Context Online")

  def fetchDataReceivedHelper(sender: str, message: Alert) -> None:
    app_context.logger.info(
      f"Message identified as '{message.identifier}' received from {message.sender}"
    )

  freshData: Signal = Signal("src_fetch_IPAWSSource")

  freshData.connect(fetchDataReceivedHelper)
  with source_factory(
    source_type=ctx.obj.source_type, uri=uri, fresh_data=freshData
  ) as dataSource:
    dataSource.run()
