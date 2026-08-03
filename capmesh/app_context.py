# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from capmesh import __app_name__
from capmesh.config.app_config import CapmeshConfig
from capmesh.logging.logging import setup_logger


class AppContext:
    """Holds all the objects needed by commands"""

    def __init__(self) -> None:
        self.app_config = CapmeshConfig(app_name=__app_name__)
        self.logger = setup_logger(log_level=self.app_config.log_level, app_name=__app_name__)
