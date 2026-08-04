# Get data from IPAWS CAP feed and cache it
# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Use APScheduler to schedule poll tasks, using httpx
# Parse CAP messages with cap-tools
# Cache data using SQLite and SQLmodel
# Clear old data from the cache using APScheduler-expiration in the CAP message


import io
import logging
import platform

import httpx
from blinker import Signal
from cap_tools.models import Alert
from httpx import URL
from tenacity import (
  before_sleep_log,
  retry,
  retry_if_exception_type,
  stop_after_attempt,
  wait_exponential,
)
from xsdata.formats.dataclass.context import XmlContext
from xsdata.formats.dataclass.parsers import XmlParser

from capmesh import __app_name__, __version__
from capmesh.core.types import AlertCache, AlertFeed

logger = logging.getLogger(name=__app_name__)


class IPAWSSource:
  """Fetches and caches CAP data from the IPAWS feed."""

  cap_received = Signal("cap_received")

  def __init__(self, feed_url: URL, database: AlertCache) -> None:
    self.feed_url: URL = feed_url
    self.database: AlertCache = database
    self.database.initialize()

    user_agent = (
      f"CapMesh/{__version__} "
      f"(+https://github.com/Theinatorinator/CAPmesh; logan.mamanakis@gmail.com) "
      f"httpx/{httpx.__version__} "
      f"Python/{platform.python_version()}"
    )
    logger.info(f"Starting IPAWS client for URL: {self.feed_url}")
    logger.debug(
      f"IPAWS client for URL: {str(self.feed_url)} has user agent: {user_agent}"
    )

    self.client = httpx.Client(headers={"User-Agent": user_agent})

  # 1. Configure Tenacity to retry on HTTP errors and connection dropouts
  @retry(
    stop=stop_after_attempt(3),  # Stop trying after 5 failures
    wait=wait_exponential(
      multiplier=1, min=2, max=16
    ),  # Wait 2s, 4s, 8s, 16s...
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.RequestError)),
    reraise=True,  # If all 5 fail, bubble up the error
    before_sleep=before_sleep_log(logger, logging.WARNING),
  )
  def fetch(self) -> str:
    """Retrieve the latest CAP feed payload with automatic exponential backoff retries."""
    logger.info(f"Starting fetch operation for URL: {self.feed_url}")

    response: httpx.Response = self.client.get(self.feed_url)

    logger.debug(f"Got Response: {response.text}")

    # 2. REQUIRED FOR TENACITY: Explicitly trigger an exception on 4xx/5xx responses
    response.raise_for_status()

    return response.text

  def parse(self, payload: str) -> list[Alert]:
    """Parse raw feed data into CAP message objects."""

    context = XmlContext()
    parser = XmlParser(context=context)
    feed: AlertFeed = parser.parse(
      io.BytesIO(payload.encode("utf-8")), AlertFeed
    )

    alerts: list[Alert] = feed.alert

    return alerts

  def poll(self) -> None:
    """Fetch and cache the latest messages from the feed."""
    try:
      payload: str = self.fetch()
      messages: list[Alert] = self.parse(payload)

      if hasattr(self.database, "save_cap_"):
        for message in messages:
          self.database.save_cap_message(data=message)

      self.cap_received.send(messages)
    except Exception as e:
      # 3. Catch final failure here so your master loop doesn't crash
      logger.critical(
        f"IPAWS Polling cycle completely failed after all retries: {e}"
      )

  def close(self) -> None:
    """Close the underlying HTTP client connection pool."""
    self.client.close()
