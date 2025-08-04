# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from typing import Any, Optional

from aws_lambda_powertools import Logger


class PowertoolsLogger:
    def __init__(self, service_name: Optional[str] = None, level: str = "info"):
        self.service_name = service_name or os.getenv("POWERTOOLS_SERVICE_NAME", "ASR")
        self._level = level.upper()
        self.logger = Logger(service=self.service_name, level=self._level)

    def debug(self, message: str, **kwargs: Any) -> None:
        if kwargs:
            self.logger.debug(message, extra=kwargs)
        else:
            self.logger.debug(message)

    def info(self, message: str, **kwargs: Any) -> None:
        if kwargs:
            self.logger.info(message, extra=kwargs)
        else:
            self.logger.info(message)

    def warning(self, message: str, **kwargs: Any) -> None:
        if kwargs:
            self.logger.warning(message, extra=kwargs)
        else:
            self.logger.warning(message)

    def error(self, message: str, **kwargs: Any) -> None:
        if kwargs:
            self.logger.error(message, extra=kwargs)
        else:
            self.logger.error(message)

    def critical(self, message: str, **kwargs: Any) -> None:
        if kwargs:
            self.logger.critical(message, extra=kwargs)
        else:
            self.logger.critical(message)

    def exception(self, message: str, **kwargs: Any) -> None:
        if kwargs:
            self.logger.exception(message, extra=kwargs)
        else:
            self.logger.exception(message)

    def add_persistent_keys(self, **kwargs: Any) -> None:
        self.logger.append_keys(**kwargs)

    def remove_keys(self, keys: list[str]) -> None:
        self.logger.remove_keys(keys)

    def set_correlation_id(self, correlation_id: str) -> None:
        self.logger.set_correlation_id(correlation_id)

    def inject_lambda_context(
        self, lambda_context: Any, log_event: bool = False
    ) -> None:
        self.logger.inject_lambda_context(lambda_context, log_event)

    def config(self, level: str = "info") -> None:
        self.logger.setLevel(level.upper())

    @property
    def level(self) -> int:
        # Convert string level to integer using logging module
        return getattr(logging, self._level, logging.INFO)

    @property
    def log(self) -> Logger:
        return self.logger


def get_logger(
    service_name: Optional[str] = None, level: str = "info"
) -> PowertoolsLogger:
    return PowertoolsLogger(service_name, level)
