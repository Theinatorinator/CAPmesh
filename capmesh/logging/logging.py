# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
import sys
from typing import Optional


def setup_logger(
  *, app_name: str, log_level: str, bind_to: Optional[logging.Logger] = None
) -> logging.Logger:
  """
  Set up logging by configuring the root logger level and stdout handler.

  All child loggers automatically inherit the root level and propagate logs to root.
  """
  level = getattr(logging, log_level.upper(), None)
  if not isinstance(level, int):
    level = logging.INFO

  # 1. Root logger holds the level AND the stdout handler
  root_logger = logging.getLogger()
  root_logger.setLevel(level)

  # Attach StreamHandler to stdout if not already attached
  has_stdout_handler = any(
    isinstance(h, logging.StreamHandler) and h.stream == sys.stdout
    for h in root_logger.handlers
  )

  if not has_stdout_handler:
    console_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
      "%(asctime)s [%(levelname)8.8s] %(name)s (%(filename)s:%(lineno)d): %(message)s"
    )
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

  # 2. Get application logger (level defaults to NOTSET, inheriting root's effective level)
  logger = logging.getLogger(app_name)

  # 3. If binding an external logger, set level to NOTSET so it inherits root level
  if bind_to is not None:
    bind_to.setLevel(logging.NOTSET)

  return logger
