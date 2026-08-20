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
from types import TracebackType

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
from capmesh.core.types import AlertFeed, PollingAlertSource

logger = logging.getLogger(name=__app_name__)


# Maybe one day we'll make this a proper singleton
class IPAWSSource(PollingAlertSource):
  """Fetches and caches CAP data from the IPAWS feed."""

  def __init__(self, feed_url: URL, fresh_data: Signal) -> None:
    self.feed_url: URL = feed_url
    self.cap_received = fresh_data

    # Use explicit, bounded timeouts so polling does not hang indefinitely
    self.timeout = httpx.Timeout(
      connect=5.0,  # DNS + TCP connect
      read=10.0,  # response reading
      write=5.0,  # request upload
      pool=5.0,  # connection pool acquisition
    )

    self.user_agent = (
      f"CapMesh/{__version__} "
      f"(+https://github.com/Theinatorinator/CAPmesh; logan.mamanakis@gmail.com) "
      f"httpx/{httpx.__version__} "
      f"Python/{platform.python_version()}"
    )
    self.client = httpx.Client(
      headers={"User-Agent": self.user_agent}, timeout=self.timeout
    )

  def __enter__(self) -> PollingAlertSource:
    logger.info(f"Starting IPAWS client for URL: {self.feed_url}")
    logger.debug(
      f"IPAWS client for URL: {str(self.feed_url)} has user agent: {self.user_agent}"
    )
    self.client.__enter__()
    return self

  # 1. Configure Tenacity to retry on HTTP errors and connection dropouts
  @retry(
    stop=stop_after_attempt(3),  # Stop trying after 3 failures
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
    """Fetch and announce the latest messages from the feed."""
    try:
      payload: str = self.fetch()
      messages: list[Alert] = self.parse(payload)

      for message in messages:
        # It might be cool to just send self as the sender, and could be very useful
        # But thats a whole lotta data to throw around without any real good purpose
        # So we will add that change if needed
        self.cap_received.send(
          self.__class__.__name__ + "---" + str(self.__hash__()),
          message=message,
        )

    except Exception as e:
      # 3. Catch final failure here so your master loop doesn't crash
      logger.critical(
        f"IPAWS Polling cycle completely failed after all retries: {e}"
      )

  def run(self) -> None:
    self.poll()

  def __exit__(
    self,
    exc_type: type[BaseException] | None = None,
    exc_val: BaseException | None = None,
    exc_tb: TracebackType | None = None,
  ) -> None:
    """Close the underlying HTTP client connection pool."""
    self.client.__exit__(exc_type, exc_val, exc_tb)
