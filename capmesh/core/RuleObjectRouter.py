# Router for CAP messages to alert sinks
# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# When notified of a new CAP message, route it to the appropriate alert sink


from typing import Dict, List, Set

from cap_tools.models import Alert
from rule_engine import Rule

from capmesh.core.types import AlertSink, Router, RuleId


class RuleObjectRouter(Router):
  """Router implementation that receives pre-compiled rule_engine.Rule objects."""

  def __init__(self) -> None:
    self._rules: Dict[RuleId, Rule] = {}
    self._rule_to_sinks: Dict[RuleId, List[AlertSink]] = {}

  def register_rule(
    self, rule_id: RuleId, rule: Rule, sinks: List[AlertSink]
  ) -> None:
    """Directly map the rule object configuration."""
    self._rules[rule_id] = rule
    self._rule_to_sinks[rule_id] = sinks

  def unregister_rule(self, rule_id: RuleId) -> None:
    """Tear down rule object and mapping configurations."""
    self._rules.pop(rule_id, None)
    self._rule_to_sinks.pop(rule_id, None)

  def route(self, alert: Alert) -> None:
    """Evaluate rules and execute the dispatch loop."""
    sinks_to_trigger: Set[AlertSink] = set()

    for rule_id, rule_obj in self._rules.items():
      if rule_obj.matches(alert):
        matching_sinks = self._rule_to_sinks.get(rule_id, [])
        sinks_to_trigger.update(matching_sinks)

    for sink in sinks_to_trigger:
      sink.send(alert)
