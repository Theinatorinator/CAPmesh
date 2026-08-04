# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
import sys
from typing import Any, Generator

import pytest

from capmesh.logging.logging import setup_logger


@pytest.fixture(autouse=True)
def reset_logging() -> Generator[None, Any, Any]:
  """Ensure clean logging state before and after each test run."""
  root = logging.getLogger()
  for handler in root.handlers[:]:
    if (
      isinstance(handler, logging.StreamHandler)
      and handler.stream == sys.stdout
    ):
      root.removeHandler(handler)
  root.setLevel(logging.NOTSET)
  logging.Logger.manager.loggerDict.clear()

  yield

  for handler in root.handlers[:]:
    if (
      isinstance(handler, logging.StreamHandler)
      and handler.stream == sys.stdout
    ):
      root.removeHandler(handler)
  root.setLevel(logging.NOTSET)
  logging.Logger.manager.loggerDict.clear()


def test_setup_logger_inherits_root_level_and_handlers() -> None:
  """Verify child logger has no direct handlers/level, but inherits root effective level."""
  app_logger = setup_logger(app_name="my_app", log_level="DEBUG")
  root_logger = logging.getLogger()

  stdout_handlers = [
    h
    for h in root_logger.handlers
    if isinstance(h, logging.StreamHandler) and h.stream == sys.stdout
  ]

  assert len(stdout_handlers) == 1
  assert len(app_logger.handlers) == 0
  assert app_logger.level == logging.NOTSET
  assert app_logger.getEffectiveLevel() == logging.DEBUG


@pytest.mark.parametrize(
  ("level_str", "expected_int_level"),
  [
    ("debug", logging.DEBUG),  # "debug" string maps to int 10
    ("INFO", logging.INFO),  # "INFO" string maps to int 20
    ("Warning", logging.WARNING),  # "Warning" string maps to int 30
    ("ERROR", logging.ERROR),  # "ERROR" string maps to int 40
    ("CRITICAL", logging.CRITICAL),  # "CRITICAL" string maps to int 50
    ("INVALID_LEVEL", logging.INFO),  # Fallback defaults to int 20
  ],
)
def test_setup_logger_level_parsing(
  level_str: str, expected_int_level: int
) -> None:
  """Verify string input translates to the correct integer effective level."""
  app_logger = setup_logger(app_name="test_app", log_level=level_str)

  # getEffectiveLevel() returns an int (e.g., 20)
  assert app_logger.getEffectiveLevel() == expected_int_level


def test_app_and_third_party_logging_output(
  caplog: pytest.LogCaptureFixture,
) -> None:
  """Verify both app and third-party logs flow through root using caplog."""
  caplog.set_level(logging.INFO)

  app_logger = setup_logger(app_name="my_app", log_level="INFO")
  third_party_logger = logging.getLogger("sqlalchemy.engine")

  app_logger.info("Application started")
  third_party_logger.info("SELECT 1 FROM users")

  assert ("my_app", logging.INFO, "Application started") in caplog.record_tuples
  assert (
    "sqlalchemy.engine",
    logging.INFO,
    "SELECT 1 FROM users",
  ) in caplog.record_tuples


def test_setup_logger_bind_to_existing_logger() -> None:
  """Verify bind_to leaves level set to NOTSET to inherit root level seamlessly."""
  external_logger = logging.getLogger("uvicorn")
  setup_logger(app_name="my_app", log_level="WARNING", bind_to=external_logger)

  assert external_logger.level == logging.NOTSET
  assert external_logger.getEffectiveLevel() == logging.WARNING
  assert len(external_logger.handlers) == 0
