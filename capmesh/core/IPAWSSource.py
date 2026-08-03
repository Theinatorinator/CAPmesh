# Get data from IPAWS CAP feed and cache it
# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Use APScheduler to schedule poll tasks, using httpx
# Parse CAP messages with cap-tools
# Cache data using SQLite and SQLmodel
# Clear old data from the cache using APScheduler-expiration in the CAP message


from blinker import Signal
from cap_tools.models import Alert

from capmesh.core.types import AlertCache


class IPAWSSource:
  """Fetches and caches CAP data from the IPAWS feed."""

  cap_received = Signal("cap_received")

  def __init__(self, feed_url: str, database: AlertCache) -> None:
    self.feed_url = feed_url
    self.database = database

  def fetch(self) -> str:
    """Retrieve the latest CAP feed payload."""
    return "<XML DATA>"

  def parse(self, payload: str) -> list[Alert]:
    """Parse raw feed data into CAP message objects."""
    data: list[Alert] = []
    return data

  def poll(self) -> None:
    """Fetch and cache the latest messages from the feed."""
    payload: str = self.fetch()
    messages: list[Alert] = self.parse(payload)
    if self.database is not None and hasattr(self.database, "save_cap_message"):
      for message in messages:
        self.database.save_cap_message(data=message)
    self.cap_received.send(messages)
    return
