# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later


import typing
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Protocol, TypeAlias

import paho.mqtt.client as mqtt
from blinker import Signal
from cap_tools.models import Alert
from rule_engine import Rule

RuleId: TypeAlias = str


class AlertSink(ABC):
  """Abstract interface for any system that consumes alerts."""

  @abstractmethod
  def send(self, data: Alert) -> None:
    """Process and transmit the alert data."""
    pass


class MQTTSink(AlertSink):
  """Concrete sink that manages a connection to a specific MQTT broker."""

  def __init__(
    self, broker_address: str, port: int = 1883, topic: str = "alerts"
  ):
    self.broker_address = broker_address
    self.port = port
    self.topic = topic
    self.client = mqtt.Client()

  def connect(self) -> None:
    """Establish the network connection and start the background loop."""
    self.client.connect(self.broker_address, self.port)
    self.client.loop_start()

  def send(self, data: Alert) -> None:
    """Publish the alert payload to this specific broker's topic."""
    # TODO: Convert CAP to string
    payload = str(data)
    self.client.publish(self.topic, payload, qos=1)

  def close(self) -> None:
    """Clean up network loops and disconnect safely."""
    self.client.loop_stop()
    self.client.disconnect()


class Router(Protocol):
  """Structural blueprint for an engine that maps rules to alert destinations."""

  @abstractmethod
  def register_rule(
    self, rule_id: RuleId, rule: Rule, sinks: List[AlertSink]
  ) -> None:
    """Compile a rule expression string and map it to onFe or many alert sinks."""
    pass

  @abstractmethod
  def unregister_rule(self, rule_id: RuleId) -> None:
    """Completely remove a rule and its associated sink mapping allocations."""
    pass

  @abstractmethod
  def route(self, alert: Alert) -> None:
    """Evaluate an incoming alert against the ruleset and dispatch it to matched sinks."""
    pass


class AlertCache(Protocol):
  """Structural blueprint for an IPAWS CAP alert message database cache."""

  def initialize(self) -> None:
    """Create required tables, schemas, and indexes for the cache."""
    ...

  @abstractmethod
  def save_cap_message(self, data: Alert) -> None:
    """Persist a CAP message instance into the database cache store."""
    ...

  @abstractmethod
  def get_cap_message(self, message_id: str) -> Alert | None:
    """Retrieve a cached CAP message object by its unique identifier string.

    Returns None if no matching record is found in the cache.
    """
    ...

  def list_cap_messages(self) -> List[Alert]:
    """Return a collection of all valid, non-expired cached CAP messages."""
    ...

  def purge_expired(self) -> None:
    """Scan the storage layer and prune expired entries from the cache."""
    ...


@dataclass
class AlertFeed:
  class Meta:
    name = "alerts"
    namespace = "http://gov.fema.ipaws.services/feed"

  alert: List[Alert] = field(
    default_factory=list,
    metadata={
      "type": "Element",
      "namespace": "urn:oasis:names:tc:emergency:cap:1.2",
    },
  )


class AlertSource(typing.ContextManager["AlertSource"], ABC):
  cap_received: Signal

  @abstractmethod
  def run(self) -> None: ...


class PollingAlertSource(AlertSource):
  @abstractmethod
  def fetch(self) -> str: ...
  @abstractmethod
  def parse(self, payload: str) -> list[Alert]: ...
  @abstractmethod
  def poll(self) -> None: ...
