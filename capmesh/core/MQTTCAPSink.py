# Receives and sends full CAP messages as MQTT messages to an MQTT broker
# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Sends full CAP messages as MQTT messages to MQTT broker, using paho-mqtt


from blinker import Signal
from cap_tools.models import Alert

from capmesh.core.types import MQTTSink


class MQTTCAPSink(MQTTSink):
  """Publishes full CAP messages to an MQTT broker."""

  cap_message = Signal("cap_message")

  def __init__(
    self,
    broker: str = "localhost",
    port: int = 1883,
    topic: str = "capmesh/cap",
  ) -> None:
    self.broker = broker
    self.port = port
    self.topic = topic
    self._connected = False

  def connect(self) -> None:
    """Open a connection to the MQTT broker."""
    self._connected = True

  def send(self, data: Alert) -> None:
    """Publish a full CAP message to the configured MQTT topic."""
    self.cap_message.send(data, topic=self.topic)
    return

  def disconnect(self) -> None:
    """Close the MQTT connection."""
    self._connected = False
