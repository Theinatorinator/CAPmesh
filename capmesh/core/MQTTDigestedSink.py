# Sinks and sends digested CAP messages as MQTT messages to MQTT broker
# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Sends digested CAP messages as MQTT messages to MQTT broker, using paho-mqtt
# Digests CAP messages so they are ready for direct human consumption
# Perfect for things like meshtastic binding


from blinker import Signal
from cap_tools.models import Alert

from capmesh.core.types import MQTTSink


class MQTTDigestedSink(MQTTSink):
  """Publishes a human-friendly digest of CAP messages to MQTT."""

  digested_message = Signal("digested_message")

  def __init__(
    self,
    broker: str = "localhost",
    port: int = 1883,
    topic: str = "capmesh/digested",
  ) -> None:
    self.broker = broker
    self.port = port
    self.topic = topic
    self._connected = False

  def connect(self) -> None:
    """Open a connection to the MQTT broker."""
    self._connected = True

  def digest(self, cap_message: Alert) -> str:
    """Convert a CAP message to a concise digest payload."""
    return str(cap_message)

  def send(self, data: Alert) -> None:
    """Publish the digested version of a CAP message."""
    payload = self.digest(data)
    self.digested_message.send(payload, topic=self.topic)
    return

  def disconnect(self) -> None:
    """Close the MQTT connection."""
    self._connected = False
